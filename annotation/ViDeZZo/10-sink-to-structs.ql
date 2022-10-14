/**
 * @id cpp/videzzo/10-sink-to-structs
 * @name Get all DMA accesses
 * @description Get all DMA accesses via signature functions
 * @kind metric
 * @tags videzzo
 */

import cpp
import ViDeZZo.videzzo

from Call call
where
  functionCallOrVariableCall(call) and
  isDMAAccess(call) and
  isSupported(call) and
  not isDuplicated(call)
select call.getFile().getRelativePath() as pathname, call.getEnclosingFunction() as function,
  getCallsiteLiteral(call) as callSite, getDestination(call) as destination,
  getExprLiteral(destination) as destinationLiteral, destination.getType() as type,
  destination.getType().stripType() as stripedType, getDestinationSize(call) as destinationSize,
  call.getLocation() as location
