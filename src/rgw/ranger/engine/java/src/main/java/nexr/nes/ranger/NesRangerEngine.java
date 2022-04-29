package nexr.nes.ranger;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import java.util.Set;
import java.util.HashSet;

import java.util.Arrays;
import java.util.List;

import org.apache.ranger.authorization.hadoop.config.RangerPluginConfig;
import org.apache.ranger.authorization.hadoop.config.RangerAuditConfig;

import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;

public class NesRangerEngine {
  private final static Logger logger = Logger.getLogger(NesRangerEngine.class);

  private RangerBasePlugin basePlugin;
  private String serviceType;
  private String appId;
  private String cacheDir;

  public NesRangerEngine(String serviceType, String appId, String cacheDir) {
    logger.debug("==> NesRangerEngine(" + serviceType + ", " + appId + ")");

    if (cacheDir == null) { cacheDir = ""; }

    this.serviceType = serviceType;
    this.appId = appId;
    this.cacheDir = cacheDir;

    logger.debug("<== NesRangerEngine(" + serviceType + ", " + appId + ")");
  }

  public NesRangerEngine(String appId, String cacheDir) {
    this("s3", appId, cacheDir);
  }

  public NesRangerEngine(String appId) {
    this("s3", appId, "");
  }

  public NesRangerEngine() {
    this("s3", "unknown", "");
  }

  public void setCacheDir(String path) {
    this.cacheDir = path;
  }

  public void ping() {
    logger.info("==> ping()");
    logger.info("NesRangerEngine says 'pong!!'");
    logger.info("<== ping()");
  }

  public boolean isAccessAllowed(String serviceName, String rangerUrl, String path, String accessType, String user, String group, String[] addrTrace) throws Exception {
    logger.debug("==> isAccessAllowed(" + serviceName + ", " + rangerUrl + ", " + path + ", " + accessType + ", " + user + ", " + group + ", " + addrTrace + ")");

    if ( (basePlugin == null)
      || (basePlugin != null && basePlugin.getServiceName() != serviceName) )
    {
      RangerPluginConfig conf = new RangerPluginConfig(serviceType, serviceName, appId, null, null, null);
      conf.set("ranger.plugin." + serviceType + ".policy.rest.url", rangerUrl);
      conf.set("ranger.plugin." + serviceType + ".policy.cache.dir", cacheDir);

			logger.debug("RangerPluginConfig: " + conf);

      basePlugin = new RangerBasePlugin(conf);
      try {
        basePlugin.init();
        basePlugin.setResultProcessor(new RangerDefaultAuditHandler());
      }
      catch (NullPointerException e) {
        logger.error(String.format("Ranger serviceType or appId not found (serviceType=%s, appId=%s): ", basePlugin.getServiceType(), basePlugin.getAppId()));
        throw e;
      }
      catch (Exception e) {
        logger.error("Unknown exception from Ranger plugin caught");
        throw e;
      }
    }

    Set<String> userGroups = new HashSet<String>();
    userGroups.add(group);

    RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
    resource.setValue("path", path); // "path" must be a value resource name in servicedef JSON
    resource.setOwnerUser(serviceName);

    RangerAccessRequestImpl request = new RangerAccessRequestImpl(resource, accessType, user, userGroups, null);
    if (addrTrace.length > 0) {
      List<String> forwardedAddrList = Arrays.asList(Arrays.copyOfRange(addrTrace, 1, addrTrace.length));

      String clientAddr = addrTrace[0];
      String remoteAddr = addrTrace[addrTrace.length - 1];

      request.setForwardedAddresses(forwardedAddrList);
      request.setClientIPAddress(clientAddr);
      request.setRemoteIPAddress(remoteAddr);
    }

		logger.debug("RangerAccessRequestImpl: " + request);

    RangerAccessResult result = basePlugin.isAccessAllowed(request);
		logger.debug("RangerAccessResult: " + result);

    boolean is_allowed = (result != null && result.getIsAllowed());

    logger.debug("<== isAccessAllowed(" + serviceName + ", " + rangerUrl + ", " + path + ", " + accessType + ", " + user + ", " + group + ", " + addrTrace + ")");

    return is_allowed;
  }
}
