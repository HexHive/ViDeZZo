/**
 * @id cpp/videzzo/11-fieldawareness
 * @name Parse struct types.
 * @description A virtual device message is field-aware with specific
 * boundaries. In general, a sub-field is either a data field or a pointer
 * field.
 * @kind metric
 * @tags videzzo
 */

import cpp
import ViDeZZo.videzzo

from Struct struct
where isTargetStruct(struct)
select struct.getName() as name, struct.getAField() as field, field.getType() as type,
  field.getByteOffset() as offset, type.getSize() as size order by name, offset
