/**
 * @id cpp/videzzo/11-structs
 * @name Parse structs.
 * @description Show the field name, field offset, and field size.
 * @kind metric
 * @tags videzzo
 */

import cpp
import ViDeZZo.videzzo

from Struct struct
where isTargetStruct(struct)
select struct.getName() as name, struct.getAField() as field, field.getType() as type,
  field.getByteOffset() as offset, type.getSize() as size order by name, offset
