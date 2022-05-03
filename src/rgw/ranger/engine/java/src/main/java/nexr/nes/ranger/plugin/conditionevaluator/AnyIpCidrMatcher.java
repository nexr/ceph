package nexr.nes.ranger.plugin.conditionevaluator;

public class AnyIpCidrMatcher extends AbstractIpCidrMatcher {
  public AnyIpCidrMatcher() { super(); zero = false; }

  @Override
  protected boolean combine(boolean a, boolean b) { return a || b; }
}
