package nexr.nes.ranger.plugin.conditionevaluator;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import java.util.List;
import java.util.ArrayList;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.ranger.plugin.conditionevaluator.RangerAbstractConditionEvaluator;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;

/**
 * This class will be called by Ranger upon a policy condition evaluation for IP ranges
 */
abstract class AbstractIpCidrMatcher extends RangerAbstractConditionEvaluator {

  private List<SubnetUtils.SubnetInfo> cidrs;
  private boolean _allowAny;

  private final static Logger logger = Logger.getLogger(AbstractIpCidrMatcher.class);

  public AbstractIpCidrMatcher() {
    cidrs = new ArrayList<SubnetUtils.SubnetInfo>();
    _allowAny = false;
  }

  /**
   * Parses the conditions for a Ranger policy to a list of CIDR ranges
   */
  @Override
  public void init() {
    super.init();

    List<String> values = condition.getValues();

    if (values == null || values.isEmpty()) {
      logger.debug("No policy condition or empty condition values. Will match always!");
      _allowAny = true;
    } else if (values.contains("*")) {
      logger.debug("Wildcard value for policy found.  Will match always!");
      _allowAny = true;
    } else {
      for(String eachValue : values ) {
        String cidrStr = eachValue;
        if (cidrStr.indexOf('/') == -1) { cidrStr += "/32"; }

        logger.debug("Adding cidr: " + cidrStr);
        SubnetUtils utils = new SubnetUtils(cidrStr);

        utils.setInclusiveHostCount(true);
        cidrs.add(utils.getInfo());
      }
    }
  }

  /**
   * Checks for a ranger request whether the remoteIpAddress is in the CIDR range specified in the Ranger policy.
   *
   * @param request Ranger request object
   * @return True if the remoteIpAddress fits in the CIDR range
   */
  @Override
  public boolean isMatched(RangerAccessRequest request) {
    logger.debug("==> isMatched()");
    if (_allowAny) {
      logger.debug("Always matches! (allowAny flag is true)");
      return true;
    } else {
      List<String> addresses = new ArrayList<String>();
      addresses.add(request.getRemoteIPAddress());
      addresses.addAll(request.getForwardedAddresses());

      logger.debug("Checking whether IpAddresses (" + addresses +") match any CIDR range");
      boolean retBool = zero;

      for (String reqAddr : addresses) {
        retBool = combine(retBool, isRemoteAddressInCidrRange(reqAddr));
        logger.debug("check " + reqAddr + " -> " + retBool);
      }

      return retBool;
    }
  }

  protected boolean zero;
  protected abstract boolean combine(boolean a, boolean b);

  private boolean isRemoteAddressInCidrRange(String remoteIpAddress) {
    for (SubnetUtils.SubnetInfo cidr : cidrs) {
      if (cidr.isInRange(remoteIpAddress)) {
        logger.debug(remoteIpAddress + " is in " + cidr.getCidrSignature());
        return true;
      }
    }

    return false;
  }
}
