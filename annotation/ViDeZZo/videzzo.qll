/**
 * @id cpp/videzzo/videzzo
 * @name ViDeZZo Common Predicates and Functions
 * @description ViDeZZo Common Predicates and Functions
 * @kind metric
 * @tags videzzo
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

string getExprLiteral(Expr expr) {
  // Liternal: FormatLiteral, HexLiteral, LabelLiteral, NULL, OctalLiteral, TextLiteral
  result = expr.(Literal).toString() and expr instanceof Literal
  or
  result = expr.(VariableAccess).toString() and
  (
    expr instanceof VariableAccess and
    not expr instanceof PointerFieldAccess and
    not expr instanceof ValueFieldAccess
  )
  or
  result = "&" + getExprLiteral(expr.(AddressOfExpr).getOperand()) and
  expr instanceof AddressOfExpr
  or
  result =
    getExprLiteral(expr.(PointerAddExpr).getLeftOperand()) + "+" +
      getExprLiteral(expr.(PointerAddExpr).getRightOperand()) and
  expr instanceof PointerAddExpr
  or
  result =
    getExprLiteral(expr.(PointerFieldAccess).getQualifier()) + "->" +
      expr.(PointerFieldAccess).toString() and
  expr instanceof PointerFieldAccess
  or
  result =
    getExprLiteral(expr.(ValueFieldAccess).getQualifier()) + "." +
      expr.(ValueFieldAccess).toString() and
  expr instanceof ValueFieldAccess
  or
  result =
    getExprLiteral(expr.(ArrayExpr).getArrayBase()) + "." +
      getExprLiteral(expr.(ArrayExpr).getArrayOffset()) and
  expr instanceof ArrayExpr
  or
  result = "sizeof(" + getExprLiteral(expr.(SizeofExprOperator).getExprOperand()) + ")" and
  expr instanceof SizeofExprOperator
  or
  result = "*" + getExprLiteral(expr.(PointerDereferenceExpr).getOperand()) and
  expr instanceof PointerDereferenceExpr
  or
  result =
    getExprLiteral(expr.(LShiftExpr).getLeftOperand()) + " << " +
      getExprLiteral(expr.(LShiftExpr).getRightOperand()) and
  expr instanceof LShiftExpr
  or
  result =
    getExprLiteral(expr.(RShiftExpr).getLeftOperand()) + " >> " +
      getExprLiteral(expr.(RShiftExpr).getRightOperand()) and
  expr instanceof RShiftExpr
  or
  result =
    getExprLiteral(expr.(BitwiseAndExpr).getLeftOperand()) + " & " +
      getExprLiteral(expr.(BitwiseAndExpr).getRightOperand()) and
  expr instanceof BitwiseAndExpr
  or
  result =
    getExprLiteral(expr.(BitwiseOrExpr).getLeftOperand()) + " | " +
      getExprLiteral(expr.(BitwiseOrExpr).getRightOperand()) and
  expr instanceof BitwiseOrExpr
  or
  result =
    getExprLiteral(expr.(BitwiseXorExpr).getLeftOperand()) + " ^ " +
      getExprLiteral(expr.(BitwiseXorExpr).getRightOperand()) and
  expr instanceof BitwiseXorExpr
  or
  result = "~" + getExprLiteral(expr.(ComplementExpr).getOperand()) and
  expr instanceof ComplementExpr
  or
  result =
    getExprLiteral(expr.(AddExpr).getLeftOperand()) + " + " +
      getExprLiteral(expr.(AddExpr).getRightOperand()) and
  expr instanceof AddExpr
  or
  result =
    getExprLiteral(expr.(SubExpr).getLeftOperand()) + " - " +
      getExprLiteral(expr.(SubExpr).getRightOperand()) and
  expr instanceof SubExpr
  or
  result =
    getExprLiteral(expr.(MulExpr).getLeftOperand()) + " * " +
      getExprLiteral(expr.(MulExpr).getRightOperand()) and
  expr instanceof MulExpr
  or
  result = "sizeof(" + expr.(SizeofTypeOperator).getTypeOperand().toString() + ")"
  or
  result = "Unknown" and
  not expr instanceof VariableAccess and
  not expr instanceof AddressOfExpr and
  not expr instanceof PointerAddExpr and
  not expr instanceof PointerFieldAccess and
  not expr instanceof ArrayExpr and
  not expr instanceof Literal and
  not expr instanceof SizeofExprOperator and
  not expr instanceof PointerDereferenceExpr and
  not expr instanceof LShiftExpr and
  not expr instanceof RShiftExpr and
  not expr instanceof BitwiseAndExpr and
  not expr instanceof BitwiseOrExpr and
  not expr instanceof BitwiseXorExpr and
  not expr instanceof AddExpr and
  not expr instanceof SubExpr and
  not expr instanceof MulExpr and
  not expr instanceof SizeofTypeOperator
}

Expr getDestination(Call call) {
  result = call.(FunctionCall).getParent().(AssignExpr).getLValue() and
  call.(FunctionCall).getTarget().getName() = ["pci_dma_map"]  and
  call instanceof FunctionCall
  or
  result = call.getArgument(1) and
  call.(FunctionCall).getTarget().getName() = ["map_page"]  and
  call instanceof FunctionCall
  or
  result = call.(FunctionCall).getParent().(AssignExpr).getLValue() and
  call.(FunctionCall).getTarget().getName() = ["dma_memory_map"]  and
  call.getEnclosingFunction().getName() != ["map_page"] and
  call instanceof FunctionCall
  or
  result = call.getArgument(getIndexOfAddressArgument(call)) and
  call.(FunctionCall).getTarget().getName() != ["pci_dma_map"] and
  call.(FunctionCall).getTarget().getName() != ["dma_memory_map"] and
  call.(FunctionCall).getTarget().getName() != ["map_page"] and
  call instanceof FunctionCall
  or
  result = call.getArgument(getIndexOfAddressArgument(call)) and call instanceof VariableCall
}

string getValueOfALengthVariable2(Variable variable) {
  result = variable.getAnAccess().getParent().(AssignExpr).getRValue().toString() and
  exists(VariableAccess variableAccess |
    variableAccess.getTarget() = variable |
    variableAccess.isUsedAsLValue())
  or
  result = getExprLiteral(variable.getInitializer().getExpr())
}

string getValueOfALengthVariable(Expr expr) {
  result = getValueOfALengthVariable2(
    expr.(AddressOfExpr).getOperand().(VariableAccess).getTarget())
  or
  result = expr.(Literal).toString()
  or
  result = expr.(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getType().(ArrayType).getByteSize().toString()
    + "=sizeof(" + expr.(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getType() + ")"
  or
  result = "Unknow" and
  not expr instanceof AddressOfExpr and
  not expr instanceof Literal
}

string getDestinationSize(Call call) {
  result = getValueOfALengthVariable(call.(FunctionCall).getArgument(3)) and
  call.(FunctionCall).getTarget().getName() = ["map_page", "pci_dma_read"] and
  call instanceof FunctionCall
  or
  result = getValueOfALengthVariable(call.(FunctionCall).getArgument(2)) and
  call.(FunctionCall).getTarget().getName() = ["pci_dma_map", "dma_memory_map"] and
  call instanceof FunctionCall
  or
  result = getDestination(call).getType().getSize().toString() and
  not getDestination(call) instanceof AddressOfExpr and
  call.(FunctionCall).getTarget().getName() != ["pci_dma_map"] and
  call.(FunctionCall).getTarget().getName() != ["dma_memory_map"] and
  call.(FunctionCall).getTarget().getName() != ["map_page"] and
  call instanceof FunctionCall
  or
  result = getDestination(call).(AddressOfExpr).getOperand().getType().getSize().toString() and
  getDestination(call) instanceof AddressOfExpr and
  call.(FunctionCall).getTarget().getName() != ["pci_dma_map"] and
  call.(FunctionCall).getTarget().getName() != ["dma_memory_map"] and
  call.(FunctionCall).getTarget().getName() != ["map_page"] and
  call instanceof FunctionCall
  or
  result = getDestination(call).getType().getSize().toString() and call instanceof VariableCall
}

string getCallsiteLiteral(Call call) {
  result = call.(FunctionCall).toString() and call instanceof FunctionCall
  or
  result =
    "call to " + call.(VariableCall).getExpr().(PointerFieldAccess).getQualifier() + "->" +
      call.(VariableCall).getExpr().(PointerFieldAccess).toString()
}

predicate functionCallOrVariableCall(Call call) {
  call instanceof FunctionCall
  or
  call instanceof VariableCall
}

predicate isDMAAccess(Call call) {
  (
    call.(FunctionCall).getTarget().getName() =
      [
        "pci_dma_read", "phys_mem_read", "ldl_le_pci_dma", "dma_memory_read", "ldq_le_dma",
        "phys_mem_read", "lduw_le_pci_dma", "ldq_le_pci_dma", "pci_dma_map", "dma_memory_map",
        "map_page"
      ]
    or
    call.(FunctionCall).getTarget().getName() =
      [
        "ohci_read_hcca", "ohci_read_ed", "ohci_read_td", "xhci_dma_read_u32s", "get_dwords",
        "queue_read", "get_pte", "lsi_mem_read", "nvme_addr_read", "vmw_shmem_rw", "vmw_shmem_read"
      ]
  ) and
  not call.(FunctionCall).getFile().getRelativePath().matches("include%") and
  call instanceof FunctionCall
  or
  call.(VariableCall).getExpr().toString() = ["phys_mem_read"] and call instanceof VariableCall
}

int getIndexOfAddressArgument(Call call) {
  result = 1 and
  call.(FunctionCall).getTarget().getName() = ["queue_read"] and
  call instanceof FunctionCall
  or
  result = 2 and
  call.(FunctionCall).getTarget().getName() != ["queue_read"] and
  call instanceof FunctionCall
  or
  result = 2 and not call instanceof FunctionCall
}

predicate isSupported(Call call) {
  call.getFile().getRelativePath() =
    [
      "hw/audio/ac97.c", "hw/audio/cs4231a.c", "hw/audio/es1370.c", "hw/audio/intel-hda.c",
      "hw/audio/sb16.c", "hw/block/fdc.c", "hw/scsi/megasas.c", "hw/sd/sdhci.c", "hw/ide/pci.c",
      "hw/ide/ahci.c", "hw/net/e1000.c", "hw/net/e1000e_core.c", "hw/net/eepro100.c",
      "hw/net/pcnet-pci.c", "hw/net/pcnet.c", "hw/net/rtl8139.c", "hw/usb/hcd-ehci.c",
      "hw/usb/hcd-ohci.c", "hw/usb/hcd-uhci.c", "hw/usb/hcd-xhci.c"
    ]
}

predicate isDuplicated(Call call) {
  call.getEnclosingFunction().getName() =
    [
      "ohci_read_hcca", "ohci_read_ed", "ohci_read_td", "xhci_dma_read_u32s", "get_dwords",
      "queue_read", "get_pte", "lsi_mem_read", "nvme_addr_read", "vmw_shmem_rw", "vmw_shmem_read"
    ]
}

predicate isTargetStruct(Struct struct) {
  // this is derived from 10-sink-to-structs.ql
  struct.getName() =
    [
      "e1000_tx_desc", "e1000_rx_desc", "e1000_tx_desc", "pcnet_initblk32", "pcnet_initblk16",
      "pcnet_TMD", "pcnet_RMD", "mfi_frame", "mfi_init_qinfo", "mfi_frame_header", "mfi_pass_frame",
      "mfi_io_frame", "mfi_init_frame", "mfi_dcmd_frame", "mfi_abort_frame", "mfi_smp_frame",
      "mfi_stp_frame", "mfi_sgl", "EHCIqh", "EHCIitd", "EHCIsitd", "EHCIqtd", "ohci_hcca",
      "ohci_ed", "ohci_td", "ohci_iso_td", "UHCI_QH", "UHCI_TD", "XHCIEvRingSeg", "XHCITRB",
      "AHCI_SG"
    ]
}

predicate isAccessOfSpecificStructField(Struct struct, Access access) {
  access instanceof PointerFieldAccess and
  access.(PointerFieldAccess).getQualifier().getType().stripType() = struct
  or
  access instanceof ValueFieldAccess and
  access.(ValueFieldAccess).getQualifier().getType() = struct
}

predicate isTracingFunction(Function func) {
  func.getName().matches("trace%") or
  func.getName().matches("_nocheck%")
}

bindingset[i]
string toHex(int i) {
  result =
    "0x" +
      strictconcat(int digit |
        digit in [0 .. 7]
      |
        "0123456789ABCDEF".charAt(i.bitShiftRight(4 * digit).bitAnd(15)) order by digit desc
      )
}
