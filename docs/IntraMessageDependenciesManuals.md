# Intra-Message Dependencies Manuals

In this documents, we introduce how to support intra-message dependencies in a
manual way, including standard procedure, principles, and tweaks used in
practice.

## Standard procedure to support intra-message dependencies (Scalability)

1. Procedure

```
a. Target a virtual device controllable via MMIO or PIO
b. Find all potential external-data reads (pci_dma_read, ld_xxx, dma_memeory_map)
c. Analyze internal field boundaries
d. Identify field types: FIELD_RANDOM, FIELD_POINTER, FIELD_FLAG, FIELD_CONSTANT
e. Handle each field (see below) with our descriptive grammar
f. Handle dependencies
```

2. Handle each field

2.2 FIELD_POINTER

2.2.1 We use FIELD_POINTER for a pointer. If it is not necessary to do a cross
head object optimization (may, 2.2.1.1), we create a pointer for each head
object (2.2.1.2).

2.4 FIELD_CONSTANT

2.4.1 We use FIELD_CONSTANT for a magic number (must, 2.4.1.1), or a variable
whose value set is limited (enumerates, must, 2.4.1.2), or the length of a
buffer (may, 2.4.1.3).

2.4.2 A potential improvement is the use of fault injection. Except for the
magic number, we can provide more than it-should-be candidated values to tease
virtual devices. In any case, if we can decide it's not helpful if to provide
more, we provide it-should-be candidated values.

------------------------------

## Tweaks to maximize representative ability

3. Union Type

```
# partial order of field types, the more right, the more concrete
FIELD_RANDOM < FIELD_POINTER <= FIELD_FLAG < FIELD_CONSTANT
```

3.1 Before analyzing the internal field boundaries, we have to obtain this
object's type. Most of time, the object has one and one only well-defined types
(must, 3.1.1).

3.2 We apply a round-robin selection when a object's type is one of the types
whose size are the same or whose shapes are shared, determined by a flag in the
header of this object (must, 3.2.1) or other constraints (may, 3.2.2). For
3.2.2, we support common fields used by different types and perform an
under-approximation on other fields. We try to use a more concrete type
(pointer, flag, or constant) for a field. We don't analyze the constraints
because they used to be related to an internal variable of a virtual device,
which is difficult to model.

3.3 Within a well-defined types, we will meet unions (may, 3.3.1). To handle
internal-unions (we can regard multiple object types as exgernal-unions), we do
a under-approximation. We try to use a more concrete type (pointer, flag, or
constant) for a field.
