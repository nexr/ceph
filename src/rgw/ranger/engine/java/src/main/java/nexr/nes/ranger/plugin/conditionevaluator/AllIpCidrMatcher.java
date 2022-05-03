package nexr.nes.ranger.plugin.conditionevaluator;

public class AllIpCidrMatcher extends AbstractIpCidrMatcher {
  public AllIpCidrMatcher() { super(); zero = true; }

  @Override
  protected boolean combine(boolean a, boolean b) { return a && b; }
}

