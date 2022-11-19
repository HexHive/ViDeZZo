/**
 * @id cpp/videzzo/13-pointers
 * @name Parse pointers in the structs
 * @description Virtual device message may involve pointers.
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
    exists(Call call |
      functionCallOrVariableCall(call) and
      (isDMAAccess(call) or call.(FunctionCall).getTarget().getName() =
       ["dma_memory_rw", "qemu_sglist_add", "pci_dma_write", "phys_mem_write", "xhci_dma_write_u32s"]) and
      isSupported(call) and
      not isDuplicated(call)
    |
      call.getArgument(1) = sink.asExpr().(VariableAccess)
      or
      call.getArgument(1) = sink.asExpr().getParent()
    )
    // or
    // sink.asExpr() instanceof Expr
  }
}

string getDestinationFunction(Access access0) {
  result = getExprLiteral(access0.getParent().(BitwiseAndExpr).getParent().(FunctionCall))
  or
  result = getExprLiteral(access0.getParent().(FunctionCall))
  or
  result = "Unknown"// and
  // not access0.getParent() instanceof BitwiseAndExpr and
  // not access0.getParent() instanceof FunctionCall
}

from
  Access access, Access access0,
  IsFlowingToDMAAccessConfiguration isFlowingToDMAAccessConfiguration
where
  isFlowingToDMAAccessConfiguration
    .hasFlow(DataFlow::exprNode(access), DataFlow::exprNode(access0)) and
  access.getFile().getRelativePath() = access0.getFile().getRelativePath() and
  // add this to avoid "infinite loop"
  isSupportedFile(access.getFile().getRelativePath())
select access.getFile().getRelativePath() as src_pathname,
  access.getEnclosingFunction() as src_function, access as src_access,
  access0.getFile().getRelativePath() as dst_pathname,
  // getDestinationFunction(access0) as dst_function,
  access0 as dst_access