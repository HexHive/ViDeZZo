/**
 * @id cpp/videzzo/12-bitawareness
 * @name Parse bitaware information for structs
 * @description Virtual device message may be bit-aware with specific flag bits
 * in a data field or a pointer field.
 * @kind metric
 * @tags videzzo
 */

import cpp
import ViDeZZo.videzzo
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

string getFlags(BitwiseAndExpr bitwise) {
  result = toHex(bitwise.getRightOperand().toString().toInt()) and
  bitwise.getRightOperand() instanceof Literal
  or
  result =
    toHex(bitwise.getRightOperand().(LShiftExpr).getLeftOperand().toString().toInt()) + " << " +
      bitwise.getRightOperand().(LShiftExpr).getRightOperand().toString() and
  bitwise.getRightOperand() instanceof LShiftExpr
}

class IsFlowingToBitwiseAndExprConfiguration extends TaintTracking::Configuration {
  IsFlowingToBitwiseAndExprConfiguration() { this = "isFlowingToBitwiseAndExprConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(Call call |
      functionCallOrVariableCall(call) and
      isDMAAccess(call) and
      isSupported(call) and
      not isDuplicated(call)
    |
      getDestination(call) = source.asExpr()
      or
      getDestination(call).(AddressOfExpr).getOperand() = source.asExpr()
      or
      isAccessOfSpecificStructField(getDestination(call).getType().stripType().(Struct),
        source.asExpr())
    )
  }

  override predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof BitwiseAndExpr }
}

from
  Access access, BitwiseAndExpr bitwiseAndExpr,
  IsFlowingToBitwiseAndExprConfiguration isFlowingToBitwiseAndExprConfiguration
where
  isFlowingToBitwiseAndExprConfiguration
      .hasFlow(DataFlow::exprNode(access), DataFlow::exprNode(bitwiseAndExpr))
select access.getFile().getRelativePath() as pathname, access.getEnclosingFunction() as function,
  access, getExprLiteral(access) as accessLiteral, bitwiseAndExpr.getLeftOperand() as flowToField,
  getExprLiteral(flowToField) as flowToFieldLiternal, getFlags(bitwiseAndExpr) as bits
