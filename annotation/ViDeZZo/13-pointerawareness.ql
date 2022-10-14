/**
 * @id cpp/videzzo/13-pointerawareness
 * @name Parse pointeraware information for structs
 * @description Virtual device message may be pointer-aware with pointers.
 * @kind metric
 * @tags videzzo
 */

import cpp
import ViDeZZo.videzzo
import semmle.code.cpp.dataflow.DataFlow


class IsFlowingToDMAAccessConfiguration extends TaintTracking::Configuration {
  IsFlowingToDMAAccessConfiguration() { this = "IsFlowingToDMAAccessConfiguration" }

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

  override predicate isSink(DataFlow::Node sink) {
    // isDMAAccess(sink.asExpr().(Call))
    sink.asExpr() instanceof Call
  }
}

from
  Access access, Call call,
  IsFlowingToDMAAccessConfiguration isFlowingToDMAAccessConfiguration
where
  isFlowingToDMAAccessConfiguration
    .hasFlow(DataFlow::exprNode(access), DataFlow::exprNode(call))
select access, getExprLiteral(access),
  getDestination(call) as destination,
  destination.getType() as type,
  destination.getType().stripType() as stripedType,
  getDestinationSize(call) as destinationSize