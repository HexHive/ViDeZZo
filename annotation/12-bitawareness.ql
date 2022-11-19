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
      getDestination(call) = source.asExpr().(VariableAccess)
      or
      getDestination(call).(AddressOfExpr).getOperand() = source.asExpr().(VariableAccess)
      or
      // handle s->configuration[20]
      getDestination(call).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase() = source.asExpr().(PointerFieldAccess)
    )
    or
    isAccessOfSpecificStructFieldSimple(source.asExpr())
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof BitwiseAndExpr or
    // &=
    sink.asExpr() instanceof AssignAndExpr
   }
}

from
  Access access, Expr bitwiseAndExpr,
  IsFlowingToBitwiseAndExprConfiguration isFlowingToBitwiseAndExprConfiguration
where
  isFlowingToBitwiseAndExprConfiguration
      .hasFlow(DataFlow::exprNode(access), DataFlow::exprNode(bitwiseAndExpr)) and
  access.getFile().getRelativePath() = bitwiseAndExpr.getFile().getRelativePath()
select access.getFile().getRelativePath() as src_pathname,
  access.getEnclosingFunction() as src_function, access,
  bitwiseAndExpr.getFile().getRelativePath() as dst_pathname,
  bitwiseAndExpr.getEnclosingFunction() as dst_function, bitwiseAndExpr,
  getExprLiteral(bitwiseAndExpr) as bitwiseAndExprLiteral
  //, getFlags(bitwiseAndExpr) as bits
