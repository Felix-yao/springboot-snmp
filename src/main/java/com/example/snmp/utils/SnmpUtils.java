package com.example.snmp.utils;

/**
 * @ClassName : SnmpUtils
 * @Description :
 * @Author : felix
 * @Date: 2022-02-28 10:55
 */
import com.alibaba.fastjson.JSON;
//import com.cecjx.common.config.DictRedisConfig;
//import com.cecjx.common.domain.DictDO;
//import com.cecjx.oamonitor.domain.SnmpOid;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SnmpUtils {
	private static final Logger logger = Logger.getLogger(SnmpUtils.class);

	public static CommunityTarget createDefault(String ip, String community, String port) {
		if (StringUtils.isBlank(ip)) {
			throw new NullPointerException("ip is null.");
		}

		if (StringUtils.isBlank(community)) {
			throw new NullPointerException("community is null.");
		}

		Address address = GenericAddress.parse("udp:" + ip + "/" + port);
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString(community));
		target.setAddress(address);
		target.setVersion(SnmpConstants.version2c);
		target.setTimeout(3000);
		target.setRetries(5);
		return target;
	}


	public static List<Map<String, String>> snmpGet(String ip, String community, String port, String oid) {
		if (StringUtils.isBlank(ip)) {
			throw new NullPointerException("ip is null.");
		}

		if (StringUtils.isBlank(community)) {
			throw new NullPointerException("community is null.");
		}

		List<Map<String, String>> list = null;
		CommunityTarget target = createDefault(ip, community, port);
		Snmp snmp = null;
		try {
			PDU pdu = new PDU();
			pdu.add(new VariableBinding(new OID(oid)));
			DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			snmp.listen();

			pdu.setType(PDU.GET);
			ResponseEvent respEvent = snmp.send(pdu, target);

			PDU response = respEvent.getResponse();
			if (null != response && response.size() > 0) {
				list = new ArrayList<Map<String, String>>();
				for (VariableBinding vb : response.getVariableBindings()) {
					Map<String, String> map = new HashMap<String, String>();
					map.put(oid, vb.toValueString());
					list.add(map);
				}
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
		} finally {
			closeSnmp(snmp);
		}
		return list;
	}

	public static void snmpGetList(String ip, String community, String port, List<String> oidList) {
		if (StringUtils.isBlank(ip)) {
			throw new NullPointerException("ip is null.");
		}

		if (StringUtils.isBlank(community)) {
			throw new NullPointerException("community is null.");
		}

		if (null == oidList || oidList.isEmpty()) {
			throw new NullPointerException("oidList is null.");
		}

		CommunityTarget target = createDefault(ip, community, port);
		Snmp snmp = null;
		try {
			PDU pdu = new PDU();

			for (String oid : oidList) {
				pdu.add(new VariableBinding(new OID(oid)));
			}

			DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			snmp.listen();
			pdu.setType(PDU.GET);
			ResponseEvent respEvent = snmp.send(pdu, target);
			PDU response = respEvent.getResponse();
			if (null != response && response.size() > 0) {
				for (VariableBinding vb : response.getVariableBindings()) {
					logger.info(vb.getOid() + " = " + vb.getVariable());
				}
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
		} finally {
			closeSnmp(snmp);
		}
	}

	public static void snmpAsynGetList(String ip, String community, String port, List<String> oidList) {
		if (StringUtils.isBlank(ip)) {
			throw new NullPointerException("ip is null.");
		}

		if (StringUtils.isBlank(community)) {
			throw new NullPointerException("community is null.");
		}

		if (null == oidList || oidList.isEmpty()) {
			throw new NullPointerException("oidList is null.");
		}

		CommunityTarget target = createDefault(ip, community, port);
		Snmp snmp = null;
		try {
			PDU pdu = new PDU();

			for (String oid : oidList) {
				pdu.add(new VariableBinding(new OID(oid)));
			}

			DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			snmp.listen();
			pdu.setType(PDU.GET);

			/*异步获取*/
			final CountDownLatch latch = new CountDownLatch(1);
			ResponseListener listener = new ResponseListener() {
				@Override
				public void onResponse(ResponseEvent event) {
					((Snmp) event.getSource()).cancel(event.getRequest(), this);
					PDU response = event.getResponse();
					if (null != response && response.size() > 0) {
						for (VariableBinding vb : response.getVariableBindings()) {
							logger.info(vb.getOid() + " = " + vb.getVariable());
						}
						latch.countDown();
					}
				}
			};

			pdu.setType(PDU.GET);
			snmp.send(pdu, target, null, listener);
			boolean wait = latch.await(30, TimeUnit.SECONDS);
			snmp.close();
		} catch (Exception e) {
			logger.error(e.getMessage());
		} finally {
			closeSnmp(snmp);
		}
	}

	public static Map<String, String> snmpWalk(String ip, String community, String port, String targetOid) {
		CommunityTarget target = createDefault(ip, community, port);
		TransportMapping transport = null;
		Snmp snmp = null;
		Map<String, String> map = new HashMap();
		try {
			transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			transport.listen();

			PDU pdu = new PDU();
			OID targetOID = new OID(targetOid);
			pdu.add(new VariableBinding(targetOID));

			boolean finished = false;
			while (!finished) {
				VariableBinding vb = null;
				ResponseEvent respEvent = snmp.getNext(pdu, target);

				PDU response = respEvent.getResponse();

				if (null == response) {
					System.out.println("responsePDU == null");
					finished = true;
					break;
				} else {
					vb = response.get(0);
				}
				finished = checkWalkFinished(targetOID, pdu, vb);
				if (!finished) {
					logger.info(vb.getOid() + " = " + vb.getVariable());
					pdu.setRequestID(new Integer32(0));
					pdu.set(0, vb);
					map.put(vb.getOid().toString(), vb.getVariable().toString());
				} else {
					snmp.close();
				}
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
		} finally {
			closeSnmp(snmp);
		}
		return map;
	}

	public static void closeSnmp(Snmp snmp) {
		try {
			if (null != snmp) {
				snmp.close();
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
	}

	private static boolean checkWalkFinished(OID targetOID, PDU pdu, VariableBinding vb) {
		boolean finished = false;
		if (pdu.getErrorStatus() != 0) {
			logger.info("[true] responsePDU.getErrorStatus() != 0");
			logger.info(pdu.getErrorStatusText());
			finished = true;
		} else if (vb.getOid() == null) {
			logger.info("[true] vb.getOid() == null");
			finished = true;
		} else if (vb.getOid().size() < targetOID.size()) {
			logger.info("[true] vb.getOid().size() < targetOID.size()");
			finished = true;
		} else if (targetOID.leftMostCompare(targetOID.size(), vb.getOid()) != 0) {
			logger.info("[true] targetOID.leftMostCompare() != 0");
			finished = true;
		} else if (Null.isExceptionSyntax(vb.getVariable().getSyntax())) {
			logger.info("[true] Null.isExceptionSyntax(vb.getVariable().getSyntax())");
			finished = true;
		} else if (vb.getOid().compareTo(targetOID) <= 0) {
			logger.info("[true] Variable received is not " + "lexicographic successor of requested " + "one:");
			logger.info(vb.toString() + " <= " + targetOID);
			finished = true;
		}
		return finished;

	}

	public static String getPrintSize(long size) {
		//如果字节数少于1024，则直接以B为单位，否则先除于1024，后3位因太少无意义
		if (size < 1024) {
			return String.valueOf(size) + "B";
		} else {
			size = size / 1024;
		}
		//如果原字节数除于1024之后，少于1024，则可以直接以KB作为单位
		//因为还没有到达要使用另一个单位的时候
		//接下去以此类推
		if (size < 1024) {
			return String.valueOf(size) + "KB";
		} else {
			size = size / 1024;
		}
		if (size < 1024) {
			//因为如果以MB为单位的话，要保留最后1位小数，
			//因此，把此数乘以100之后再取余
			size = size * 100;
			return String.valueOf((size / 100)) + "."
					+ String.valueOf((size % 100)) + "MB";
		} else {
			//否则如果要以GB为单位的，先除于1024再作同样的处理
			size = size * 100 / 1024;
			return String.valueOf((size / 100)) + "."
					+ String.valueOf((size % 100)) + "GB";
		}
	}

	//从redis获取字典表里的oid数据
//	public static SnmpOid getOid(RedisUtil redisUtil, String oidType) {
//		SnmpOid snmpOid = new SnmpOid();
//		Object obj = redisUtil.getObject(DictRedisConfig.dictResisPrefix + oidType);
//		List<DictDO> oidList = JSON.parseArray(redisUtil.getObject(DictRedisConfig.dictResisPrefix + oidType).toString(), DictDO.class);
//		if (oidList.size() > 0) {
//			for (DictDO dictDO : oidList) {
//				switch (dictDO.getName()) {
//					case "sysDescOid":
//						snmpOid.setSysDescOid(dictDO.getValue());
//						break;
//					case "ramTotalOid":
//						snmpOid.setRamTotalOid(dictDO.getValue());
//						break;
//					case "ramAvailableOid":
//						snmpOid.setRamAvailableOid(dictDO.getValue());
//						break;
//					case "ramSharedOid":
//						snmpOid.setRamSharedOid(dictDO.getValue());
//						break;
//					case "ramBufferOid":
//						snmpOid.setRamBufferOid(dictDO.getValue());
//						break;
//					case "ramCachedOid":
//						snmpOid.setRamCachedOid(dictDO.getValue());
//						break;
//					case "cpuProcessorLoadOid":
//						snmpOid.setCpuProcessorLoadOid(dictDO.getValue());
//						break;
//					case "diskPathOid":
//						snmpOid.setDiskPathOid(dictDO.getValue());
//						break;
//					case "diskTypeOid":
//						snmpOid.setDiskTypeOid(dictDO.getValue());
//						break;
//					case "diskAllocationUnitsOid":
//						snmpOid.setDiskAllocationUnitsOid(dictDO.getValue());
//						break;
//					case "diskStorageSizeOid":
//						snmpOid.setDiskStorageSizeOid(dictDO.getValue());
//						break;
//					case "diskUsedOid":
//						snmpOid.setDiskUsedOid(dictDO.getValue());
//						break;
//					case "mainDiskUsedOid":
//						snmpOid.setMainDiskUsedOid(dictDO.getValue());
//						break;
//					case "sendOid":
//						snmpOid.setSendOid(dictDO.getValue());
//						break;
//					case "receiveOid":
//						snmpOid.setReceiveOid(dictDO.getValue());
//						break;
//					case "cpuIdleOId":
//						snmpOid.setCpuIdleOId(dictDO.getValue());
//						break;
//				}
//			}
//			return snmpOid;
//		} else {
//			return null;
//		}
//	}

	//统一判断snmp的返回数据是否有误
	public static Boolean ifListTrue(List<Map<String, String>> list, String oid) {
		return list != null && list.size() > 0 && list.get(0).get(oid) != null && !list.get(0).get(oid).equals("noSuchInstance") && !list.get(0).get(oid).equals("noSuchObject");
	}


	public static String getChinese(String octetString) {    //snmp4j遇到中文直接转成16进制字符串
		try {
			String[] temps = octetString.split(":");
			byte[] bs = new byte[temps.length];
			for (int i = 0; i < temps.length; i++)
				bs[i] = (byte) Integer.parseInt(temps[i], 16);
			return new String(bs, "GB2312");
		} catch (Exception e) {
			return octetString;
		}
	}


	public static void main(String[] args) {

//		String memTotal = ".1.3.6.1.4.1.2021.4.5.0";
//		String memAvailable = ".1.3.6.1.4.1.2021.4.6.0";
//		String memShared = ".1.3.6.1.4.1.2021.4.13.0";
//		String memBuffer = ".1.3.6.1.4.1.2021.4.14.0";
//		String memCached = ".1.3.6.1.4.1.2021.4.15.0";
//		List<Map<String, String>> memTotalList = SnmpUtils.snmpGet("", "public", "161", memTotal);
//		List<Map<String, String>> memAvailableList = SnmpUtils.snmpGet("", "public", "161", memAvailable);
//		List<Map<String, String>> memSharedList = SnmpUtils.snmpGet("", "public", "161", memShared);
//		List<Map<String, String>> memBufferList = SnmpUtils.snmpGet("", "public", "161", memBuffer);
//		List<Map<String, String>> memCachedList = SnmpUtils.snmpGet("", "public", "161", memCached);
//
//		Long memTotalTemp = Long.parseLong(memTotalList.get(0).get(memTotal));
//		Long memAvailableTemp = Long.parseLong(memAvailableList.get(0).get(memAvailable));
//		Long memSharedTemp = Long.parseLong(memSharedList.get(0).get(memShared));
//		Long memBufferTemp = Long.parseLong(memBufferList.get(0).get(memBuffer));
//		Long memCachedTemp = Long.parseLong(memCachedList.get(0).get(memCached));
//
//		if (memSharedTemp + memAvailableTemp + memCachedTemp > memTotalTemp) {
//			Long temp = memTotalTemp - memAvailableTemp - memBufferTemp - memCachedTemp + memSharedTemp;
//			String used = new DecimalFormat("0").format(temp * 100 / memTotalTemp);
//			System.out.println(temp);
//			System.out.println(memTotalTemp);
//			System.out.println(used);
//			System.out.println("111");
//		} else {
//			Long temp = memTotalTemp - memAvailableTemp - memBufferTemp - memCachedTemp;
//			String used = new DecimalFormat("0").format(temp * 100 / memTotalTemp);
//			System.out.println(temp);
//			System.out.println(memTotalTemp);
//			System.out.println(used);
//			System.out.println("222");
//		}

		String memTotal = ".1.3.6.1.2.1.1.3.0";
		List<Map<String, String>> memTotalList = SnmpUtils.snmpGet("192.168.1.222", "public", "161", memTotal);
//		Long memTotalTemp = Long.parseLong(memTotalList.get(0).get(memTotal));
		System.out.println(memTotalList.get(0).get(memTotal));

		Map<String, String> map = SnmpUtils.snmpWalk("192.168.1.222", "public", "161", memTotal);

		System.out.println(map);

	}

}

