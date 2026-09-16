# Requirements Document

## Introduction

This specification covers the image steganography and image steganalysis layer of the INF2005 ACW1 media integrity project (Member 2 scope). The layer provides LSB replacement embedding and extraction for PNG and BMP cover objects, capacity calculation, start-location validation, image quality comparison, bit-plane visualisation, difference imaging, and statistical steganalysis indicators.

Scope boundaries, stated explicitly because this layer is one part of a five-member system:

- The layer treats the payload as opaque bytes. The layer performs no hashing, signing, signature verification, encryption, payload-envelope construction, or verdict generation. Those concerns belong to the cryptography layer (Member 1) and the verification layer (Member 5).
- The layer covers image cover objects only. Audio (Member 3) and video (Member 5) are out of scope.
- The layer contains no GUI code and no PySide6 dependency. All functions return data structures, numeric metrics, or pixel arrays that the GUI layer (Member 4) renders.
- The layer performs no attack simulation (Member 5).

The layer conforms to the shared interfaces agreed in the team planning reference:

```python
def embed_image(input_path: str, output_path: str, payload: bytes, lsb_count: int, start_location: int): ...
def extract_image(input_path: str, lsb_count: int, start_location: int) -> bytes: ...
```

The extraction interface accepts no payload-length argument. Requirement 4 therefore records the team decision that the encoded bit stream begins with a fixed-width length header, so that the extractor can determine the payload length from the cover object alone. The remaining extraction parameters, the format version, and the recorded payload length live in the companion manifest produced by other layers, not in the encoded bit stream.

Shared bit-level helpers are placed in `app/stego/bit_utils.py` and capacity arithmetic in `app/stego/capacity.py` so that the audio layer reuses the same implementations rather than duplicating bit manipulation. The shared helpers accept unsigned samples of 8-bit and 16-bit width, with the sample width supplied by the caller, so that the audio layer applies the same write and read helpers to 16-bit PCM samples while the image layer uses the 8-bit width. Both shared components take and return only integers, integer arrays, and byte sequences, and perform no file access.

Alpha-channel samples are treated asymmetrically across this layer, and the asymmetry is deliberate:

- Embedding and extraction exclude alpha-channel samples. The Byte_Stream of Requirement 2 contains colour-channel samples only, so an RGBA cover object has the same Embeddable_Byte count as its RGB equivalent, and alpha samples are carried through to the stego object unchanged.
- Capacity arithmetic follows the same exclusion, reporting an embeddable channel count of 3 for both RGB and RGBA images.
- Difference imaging (Requirement 10) and bit-plane extraction (Requirement 9) include alpha-channel samples, because those views describe what changed in a file rather than what can carry payload bits, and an unexpected alpha change is itself worth showing.
- Quality comparison (Requirement 8) excludes alpha samples from the overall MSE and PSNR, to keep the headline distortion figures aligned with the samples that embedding can touch, and reports the alpha-channel MSE and PSNR as separately labelled per-channel values.

This layer provides no confidentiality and no authenticity guarantee. Concealment of a payload location is not encryption, and the steganalysis indicators in Requirement 11 are heuristics, not reliable detectors.

## Glossary

- **Cover_Object**: The original unmodified image file supplied as input to embedding.
- **Stego_Object**: The image file produced by embedding a payload into a Cover_Object.
- **Payload**: The opaque sequence of bytes supplied by a caller for embedding. This layer assigns no meaning to Payload content.
- **LSB_Depth**: The number of least significant bits, from 1 to 8 inclusive, written in each Embeddable_Byte. Referenced in code as `lsb_count`.
- **Embeddable_Byte**: One 8-bit colour-channel sample of the decoded image that is eligible to carry Payload bits. Alpha-channel samples are excluded (see Requirement 2).
- **Byte_Stream**: The ordered sequence of all Embeddable_Byte values of a decoded image, in Traversal_Order.
- **Traversal_Order**: Row-major pixel order from the top-left pixel to the bottom-right pixel, and within each pixel the colour channels in decoded channel order, which is the single channel for a grayscale image and red then green then blue for an RGB or RGBA image. Traversal_Order is defined on the top-down sample array produced by decoding, so a bottom-up stored BMP yields the same Traversal_Order as its top-down equivalent.
- **Start_Location**: A zero-based index into the Byte_Stream identifying the first Embeddable_Byte that carries Encoded_Stream bits. Referenced in code as `start_location`.
- **Length_Header**: A 4-byte big-endian unsigned integer that precedes the Payload in the Encoded_Stream and records the Payload length in bytes. The Length_Header carries no integrity or authenticity protection at this layer.
- **Encoded_Stream**: The concatenation of the Length_Header and the Payload, which is the byte sequence actually written into the Byte_Stream. The Encoded_Stream carries no format-version, type, or marker byte.
- **Capacity**: The maximum Encoded_Stream length in bytes that a given image can carry at a given LSB_Depth from a given Start_Location. Capacity therefore counts the 4 Length_Header bytes and is distinct from Max_Payload_Length.
- **Available_Capacity**: The Capacity computed from the Embeddable_Byte positions at or after a supplied Start_Location.
- **Max_Payload_Length**: The greater of 0 and the Available_Capacity minus the 4 Length_Header bytes. This is the largest Payload that fits, as distinct from Capacity.
- **Required_Position_Count**: The number of consecutive Embeddable_Byte positions an Encoded_Stream occupies at a given LSB_Depth, equal to the Encoded_Stream bit count divided by the LSB_Depth, rounded up.
- **Successful_Embedding**: An embedding operation that raises no error and writes a complete Stego_Object.
- **Companion_Manifest**: The record produced by other layers that carries the format version, the extraction parameters, and the recorded Payload length. This layer neither creates nor validates the Companion_Manifest, and reads a manifest Payload length only when a caller supplies it (see Requirement 4).
- **Bit_Plane**: The single-bit image formed by taking bit position n, where n is 0 to 7 inclusive, of every sample of one channel. Bit_Plane extraction addresses any channel of the decoded image, including the alpha channel, even though the Byte_Stream excludes alpha-channel samples.
- **Analysed_Sample**: A sample included in a steganalysis indicator computation, being an Embeddable_Byte of the supplied image, restricted to the Region_Of_Interest where one is supplied.
- **Region_Of_Interest**: A rectangular sub-area of an image given as zero-based left and top offsets with a width and a height, used to restrict steganalysis indicator computation.
- **MSE**: Mean squared error, the mean of the squared per-sample differences between two images of identical dimensions and channel count.
- **PSNR**: Peak signal-to-noise ratio in decibels, computed from MSE with a peak sample value of 255.
- **Unbounded_PSNR_Indicator**: The boolean flag accompanying a PSNR value that reports positive infinity, so that a caller renders the unbounded case without parsing text.
- **Difference_Image**: An image derived from the per-sample absolute differences between two images of identical dimensions and channel count. Alpha-channel samples are included.
- **Changed_Pixel_Map**: A boolean array of the same height and width as two compared images, true exactly where at least one channel of the corresponding pixel differs.
- **Bit_0_Uniformity_Indicator**: The chi-square statistic on 1 degree of freedom comparing the observed counts of Analysed_Sample values with bit 0 equal to 0 and equal to 1 against an even split.
- **Pair_Of_Values_Chi_Square_Indicator**: The chi-square statistic computed over the 128 histogram bin pairs formed by sample values 2k and 2k plus 1, using the mean of each pair as the expected count.
- **Pair_Of_Values_Neighbour_Indicator**: The count and proportion of horizontally adjacent same-channel sample pairs whose two values differ only in bit 0.
- **Insufficient_Sample_Status**: The result state returned in place of a numeric indicator value and threshold flag when a channel supplies too few Analysed_Sample values, too few included bin pairs, or no examined sample pairs. It is a reported status, not an error.
- **Image_Stego_Module**: The component implemented in `app/stego/image_stego.py`, providing `embed_image` and `extract_image`.
- **Image_Analysis_Module**: The component implemented in `app/analysis/image_analysis.py`, providing quality comparison, bit-plane extraction, difference imaging, and steganalysis indicators.
- **Capacity_Calculator**: The component implemented in `app/stego/capacity.py`, providing Capacity arithmetic shared with the audio layer.
- **Bit_Utils**: The component implemented in `app/stego/bit_utils.py`, providing byte-to-bit and bit-to-byte conversion and low-order-bit write and read helpers for 8-bit and 16-bit unsigned samples, shared with the audio layer.
- **Stego_Error**: The single common base exception type of this layer. Every error this layer raises is an instance of one of the five direct subclasses below, so that a caller catches one named category or the whole layer with one handler (see Requirement 14).
- **File_Error**: The Stego_Error subclass raised for filesystem faults, covering a missing input path, denied read access to an existing input path, and an absent or non-writable output directory.
- **Decode_Error**: The Stego_Error subclass raised when a readable input file cannot be decoded as an 8-bit-per-channel grayscale, RGB, or RGBA PNG or BMP image, including lossy, palette, and unsupported sample-width inputs.
- **Validation_Error**: The Stego_Error subclass raised for an argument that fails a type or range check, covering Payload type, LSB_Depth, Start_Location, bit-sequence length, sample width, output path equal to input path, and mutually exclusive difference-image modes.
- **Capacity_Error**: The Stego_Error subclass raised when the Required_Position_Count or the required Encoded_Stream length exceeds what the image provides from the supplied Start_Location.
- **Extraction_Error**: The Stego_Error subclass raised when a decoded Length_Header is inconsistent with the image Capacity, the bit stream is truncated, or a supplied manifest Payload length disagrees with the decoded Length_Header.

## Requirements

### Requirement 1: Lossless Image Loading and Saving

**User Story:** As a team member embedding data into images, I want PNG and BMP files loaded and saved without lossy transformation, so that embedded bits survive a save-and-reload cycle.

#### Acceptance Criteria

1. WHEN a caller supplies an input path whose file content is detected from the content itself, and not from the path extension, as PNG or BMP, and whose content decodes as an 8-bit-per-channel grayscale, RGB, or RGBA image with pixel dimensions from 1 by 1 up to 30000 by 30000 inclusive, THE Image_Stego_Module SHALL decode the image into a sample array of shape height by width by channel count, where the channel count is 1 for grayscale, 3 for RGB, and 4 for RGBA.
2. IF the detected content format of the input file differs from the format named by the input path extension, and the detected content format is a supported format under criterion 1, THEN THE Image_Stego_Module SHALL decode the input using the detected content format and SHALL report the detected content format alongside the extension in its returned file description.
3. WHEN THE Image_Stego_Module writes a Stego_Object, THE Image_Stego_Module SHALL write the output in the container format detected from the Cover_Object content, using lossless compression for PNG output and uncompressed sample data for BMP output, and SHALL not use the output path extension to select the output container format.
4. FOR ALL sample arrays written by THE Image_Stego_Module, reloading the written file through THE Image_Stego_Module SHALL produce a sample array equal to the written array in height, width, channel count, and every sample value including alpha-channel samples (round-trip property).
5. IF the input file content decodes to a format that applies lossy compression, including JPEG and JPEG 2000, THEN THE Image_Stego_Module SHALL reject the input with an error that names the detected content format and the supported formats PNG and BMP, SHALL create no output file, and SHALL leave the input file unmodified.
6. IF the input file content decodes to an indexed-colour (palette) image, including PNG palette colour type and 1-bit, 4-bit, and 8-bit indexed BMP variants and RLE4- or RLE8-compressed BMP variants, THEN THE Image_Stego_Module SHALL reject the input with an error stating that palette indices are unsupported, naming the detected variant, and stating that conversion to 8-bit-per-channel RGB is required before embedding, and SHALL create no output file.
7. IF the input file content decodes to an image with a sample width other than 8 bits per channel, including 1-bit, 2-bit, 4-bit, and 16-bit PNG sample widths and packed 16-bit BMP variants of 5-5-5 or 5-6-5 layout, THEN THE Image_Stego_Module SHALL reject the input with an error that reports the detected sample width in bits per channel and the supported sample width of 8 bits per channel, and SHALL create no output file.
8. WHERE the Cover_Object is a grayscale image, THE Image_Stego_Module SHALL treat the single channel as the only source of Embeddable_Byte values.
9. THE Image_Stego_Module SHALL preserve the pixel dimensions, the channel count, and the 8-bit-per-channel sample width of the Cover_Object in the Stego_Object.
10. WHEN the Cover_Object content is an interlaced PNG, THE Image_Stego_Module SHALL decode it into a sample array equal to the sample array of its non-interlaced equivalent, and SHALL write the Stego_Object as non-interlaced PNG.
11. WHEN THE Image_Stego_Module writes a PNG Stego_Object, THE Image_Stego_Module SHALL write only the records required to represent the pixel dimensions, colour type, 8-bit sample width, and sample data, and SHALL copy no ancillary metadata records of the Cover_Object into the Stego_Object.
12. WHEN the Cover_Object content is an uncompressed BMP with bottom-up row order, or an uncompressed 8-bit-per-channel BMP declaring a BITMAPINFOHEADER, BITMAPV4HEADER, or BITMAPV5HEADER variant, THE Image_Stego_Module SHALL decode it into a top-down row-major sample array whose first sample belongs to the top-left pixel, so that Traversal_Order is independent of the stored row order, and SHALL decode an uncompressed 32-bit BMP as a 4-channel image.

### Requirement 2: LSB Replacement Embedding

**User Story:** As a team member protecting an image, I want a payload written into the low-order bits of the image samples at a selectable depth, so that the payload is carried by the image with a controlled amount of distortion.

#### Acceptance Criteria

1. THE Image_Stego_Module SHALL construct the Byte_Stream by listing every Embeddable_Byte of the decoded image in Traversal_Order, where Traversal_Order visits pixels row-major from the top-left pixel to the bottom-right pixel and, within each pixel, visits the colour channels in decoded channel order, which is the single channel for a grayscale image and red then green then blue for an RGB or RGBA image.
2. THE Image_Stego_Module SHALL exclude alpha-channel samples from the Byte_Stream, so that the total Embeddable_Byte count equals width multiplied by height for a grayscale image and width multiplied by height multiplied by 3 for an RGB or RGBA image.
3. THE Image_Stego_Module SHALL construct the Encoded_Stream as the 4-byte Length_Header followed by the Payload bytes in Payload order, so that the Encoded_Stream length in bytes equals the Payload length plus 4.
4. THE Image_Stego_Module SHALL convert the Encoded_Stream to a bit sequence by taking the Encoded_Stream bytes in order and reading each byte from bit position 7 down to bit position 0, so that the bit sequence length equals 8 multiplied by the Encoded_Stream length in bytes.
5. WHEN THE Image_Stego_Module writes bits into one Embeddable_Byte at LSB_Depth n, where n is 1 to 8 inclusive, THE Image_Stego_Module SHALL replace bit positions n minus 1 down to 0 with the next n bits of the bit sequence, in descending bit-position order, so that at LSB_Depth 1 exactly bit position 0 is replaced in each written Embeddable_Byte and at LSB_Depth 8 all bit positions 7 down to 0 are replaced in each written Embeddable_Byte.
6. IF the bit sequence length is not an exact multiple of the LSB_Depth, THEN THE Image_Stego_Module SHALL append between 1 and LSB_Depth minus 1 zero bits to form the final group and SHALL write that padded group into a single Embeddable_Byte.
7. THE Image_Stego_Module SHALL write the bit sequence into the consecutive Embeddable_Byte positions from the Start_Location index through the Start_Location index plus the group count minus 1 inclusive, where the group count equals the bit sequence length divided by the LSB_Depth rounded up to the next integer, and SHALL never resume writing at an index lower than the Start_Location after reaching the last Embeddable_Byte position (no wrap-around).
8. FOR ALL successful embeddings, where a successful embedding is an embedding operation that raises no error and writes a Stego_Object, every bit at position greater than or equal to the LSB_Depth in every written Embeddable_Byte SHALL equal the corresponding bit of the Cover_Object sample (cover preservation property).
9. FOR ALL successful embeddings, every Embeddable_Byte outside the written index range and every alpha-channel sample SHALL equal the corresponding sample value in the Cover_Object (cover preservation property).
10. FOR ALL successful embeddings at LSB_Depth 1 to 7 inclusive, the absolute difference between each written Embeddable_Byte and the corresponding Cover_Object sample SHALL be less than 2 raised to the power of the LSB_Depth, and SHALL be 0 for every written Embeddable_Byte whose replaced bit positions already held the written bit group in the Cover_Object (bounded distortion property).
11. FOR ALL identical combinations of Cover_Object sample array, Payload, LSB_Depth, and Start_Location, two separate embedding operations SHALL produce Stego_Object sample arrays that are equal in dimensions, channel count, and every sample value (determinism property).
12. THE Image_Stego_Module SHALL leave the Cover_Object file byte-for-byte unchanged.
13. FOR ALL successful embeddings at LSB_Depth 8, each written Embeddable_Byte SHALL equal the unsigned integer value of its corresponding 8-bit group of the bit sequence, retaining no bit of the corresponding Cover_Object sample (full sample overwrite property).
14. WHEN the supplied Payload length is 0, THE Image_Stego_Module SHALL write an Encoded_Stream consisting only of the 4-byte Length_Header with value 0, beginning at the Start_Location index, and SHALL produce a Stego_Object without raising an error.
15. IF the supplied output path resolves to the same file as the supplied input path, THEN THE Image_Stego_Module SHALL raise a validation error indicating that the output path must differ from the input path, SHALL modify no sample, and SHALL leave the Cover_Object file byte-for-byte unchanged.

### Requirement 3: Payload Extraction

**User Story:** As a team member receiving a stego image, I want the embedded bytes recovered exactly when the correct depth and start location are supplied, so that downstream verification receives the original payload bytes.

#### Acceptance Criteria

1. WHEN a caller invokes `extract_image` on an unmodified Stego_Object with the LSB_Depth and Start_Location used at embedding time, THE Image_Stego_Module SHALL return a byte sequence equal to the embedded Payload and of length equal to the decoded Length_Header value.
2. THE Image_Stego_Module SHALL form the extraction bit sequence by taking, from each Embeddable_Byte of the Byte_Stream in Traversal_Order beginning at the Start_Location index, the LSB_Depth lowest-order bits in descending bit-position order, and SHALL concatenate those bits into one continuous bit sequence.
3. THE Image_Stego_Module SHALL decode the Length_Header from bit positions 0 to 31 of the continuous bit sequence, most-significant-bit first, SHALL read the Payload bits from bit position 32 of the same continuous bit sequence without realigning to an Embeddable_Byte boundary when the LSB_Depth does not divide 32 exactly, SHALL read exactly 8 multiplied by the decoded Length_Header value Payload bits, and SHALL discard every bit of the continuous bit sequence beyond that point, including the zero padding bits written during embedding.
4. FOR ALL Payload values whose Encoded_Stream length is within the reported Capacity, FOR ALL LSB_Depth values from 1 to 8 inclusive, including the values 3, 5, 6, and 7 that do not divide 32 exactly, and FOR ALL valid Start_Location values, extraction after embedding SHALL return a byte sequence equal to the original Payload (round-trip property).
5. WHEN the decoded Length_Header value is zero, THE Image_Stego_Module SHALL return an empty byte sequence and SHALL read no Payload bits.
6. THE Image_Stego_Module SHALL compare the decoded Length_Header value against the available Capacity from the supplied Start_Location, expressed as the available Encoded_Stream length in bytes minus the 4 Length_Header bytes, before allocating any buffer for the Payload; and IF the decoded value exceeds that available length, THEN THE Image_Stego_Module SHALL raise an extraction error stating that the decoded length is inconsistent with the image Capacity, SHALL allocate no Payload buffer, and SHALL return no bytes.
7. IF fewer than 32 bits are available from the Start_Location to the end of the Byte_Stream, or fewer than 8 multiplied by the decoded Length_Header value bits remain after bit position 31 of the continuous bit sequence, THEN THE Image_Stego_Module SHALL raise an extraction error stating that the bit stream is truncated and SHALL return no partial byte sequence.
8. THE Image_Stego_Module SHALL open the input file for reading only, and SHALL leave the input file content, size, and Byte_Stream unmodified during extraction.
9. THE Image_Stego_Module SHALL report extraction failures without asserting a specific cause, because incorrect LSB_Depth, incorrect Start_Location, absent payload, and sample corruption produce indistinguishable bit streams.
10. IF the supplied LSB_Depth or Start_Location differs from the values used at embedding, THEN THE Image_Stego_Module SHALL either raise an extraction error as specified in criteria 6 and 7 or return a byte sequence that is not required to equal the embedded Payload, and SHALL NOT report the returned byte sequence as verified or authentic, because a mismatched read can decode a Length_Header value that lies within the available Capacity and yield plausible-but-wrong bytes without error.
11. FOR ALL identical combinations of input file, LSB_Depth, and Start_Location, two separate extraction operations SHALL return equal byte sequences, or SHALL both raise the same extraction error type (determinism property).

### Requirement 4: Payload Length Recovery Decision

**User Story:** As a team member calling the agreed extraction interface, I want the payload length recoverable from the stego image alone, so that extraction works with the agreed signature that accepts no length argument.

#### Acceptance Criteria

1. THE Image_Stego_Module SHALL prefix the Payload with a Length_Header of exactly 4 bytes that encodes the Payload length in bytes as a big-endian unsigned integer in the range 0 to 4294967295 inclusive, placed immediately before the first Payload byte in the Encoded_Stream, at the same fixed width for every LSB_Depth value from 1 to 8 inclusive and every valid Start_Location.
2. THE Image_Stego_Module SHALL include the 4 Length_Header bytes in every Capacity comparison performed during embedding and during extraction, so that the required Encoded_Stream length in bytes equals the Payload length plus 4.
3. IF the Payload length exceeds 4294967295 bytes, THEN THE Image_Stego_Module SHALL reject the embedding request before modifying any sample, SHALL report the supplied Payload length and the maximum representable Payload length of 4294967295 bytes, and SHALL create no output file.
4. THE Image_Stego_Module SHALL state in its interface documentation that the Length_Header carries no integrity and no authenticity protection, that a Length_Header altered after embedding is indistinguishable at this layer from an unaltered one, and that detection of an altered Length_Header is the responsibility of the verification layer.
5. THE Image_Stego_Module SHALL define the Encoded_Stream as exactly the 4-byte Length_Header followed by the Payload bytes, with no format-version, type, or marker byte, because the format version and the remaining extraction parameters are carried by the companion manifest rather than by the Encoded_Stream.
6. IF the decoded Length_Header value exceeds the Capacity remaining from the supplied Start_Location at the supplied LSB_Depth, THEN THE Image_Stego_Module SHALL raise an extraction error reporting the decoded length and the remaining Capacity in bytes, SHALL allocate no buffer whose size is derived from the decoded Length_Header value, and SHALL return no Payload bytes.
7. WHERE the caller supplies the Payload length recorded in the companion manifest, THE Image_Stego_Module SHALL determine the number of Payload bytes to read from the decoded Length_Header, and IF the decoded Length_Header value differs from the supplied manifest Payload length, THEN THE Image_Stego_Module SHALL raise an extraction error reporting both values and SHALL return no Payload bytes.

### Requirement 5: Capacity Calculation

**User Story:** As a team member choosing an LSB depth, I want the exact carrying capacity of an image reported before embedding, so that payload size decisions are made from measured values.

#### Acceptance Criteria

1. THE Capacity_Calculator SHALL compute the total embeddable bit count as width multiplied by height multiplied by embeddable channel count multiplied by LSB_Depth, where the embeddable channel count is 1 for a grayscale image, 3 for an RGB image, and 3 for an RGBA image because alpha-channel samples are excluded from the Byte_Stream.
2. THE Capacity_Calculator SHALL compute Capacity in bytes as the total embeddable bit count divided by 8, rounded down to the nearest integer, and SHALL define Capacity as the maximum Encoded_Stream length in bytes, that is the Length_Header bytes plus the Payload bytes.
3. WHEN a caller supplies a Start_Location from 0 to the total Embeddable_Byte count minus 1 inclusive, THE Capacity_Calculator SHALL compute the available Capacity in bytes as the total Embeddable_Byte count minus the Start_Location, multiplied by the LSB_Depth, divided by 8, rounded down to the nearest integer; Start_Location values outside that range are handled by the validation rules of Requirement 7.
4. THE Capacity_Calculator SHALL report the embeddable channel count, the total Embeddable_Byte count, the supplied LSB_Depth, the available Capacity in bytes, the maximum Payload length in bytes, and a payload-fits flag that is true exactly when the maximum Payload length is greater than 0.
5. FOR ALL images, FOR ALL Start_Location values, and FOR ALL LSB_Depth values n from 2 to 8, the available Capacity reported at LSB_Depth n SHALL be greater than or equal to the available Capacity reported at LSB_Depth n minus 1 for the same image and Start_Location (non-decreasing metamorphic property); the property is non-decreasing rather than strictly increasing because rounding the bit count down to whole bytes can leave the reported Capacity unchanged between adjacent depths when fewer than 8 Embeddable_Byte positions remain.
6. THE Capacity_Calculator SHALL expose the capacity arithmetic as functions whose parameters are the total embeddable sample count as an integer, the LSB_Depth as an integer, and the Start_Location as an integer, and SHALL accept no file path, no sample array, and no media-type argument, so that the audio layer supplies its frame count multiplied by its channel count as the total embeddable sample count and reuses the same implementation.
7. THE Capacity_Calculator SHALL compute the maximum Payload length in bytes as the greater of 0 and the available Capacity minus the 4 Length_Header bytes.
8. IF the available Capacity is less than 4 bytes, THEN THE Capacity_Calculator SHALL report a maximum Payload length of 0, a payload-fits flag of false, and a capacity-used percentage of not applicable, and SHALL report these values without raising an error, because reporting that no Payload fits is a measurement result rather than an invalid request.
9. WHERE the caller supplies a Payload length and the available Capacity is greater than or equal to 4 bytes, THE Capacity_Calculator SHALL report the capacity-used percentage as the required Encoded_Stream length divided by the available Capacity multiplied by 100, rounded to one decimal place and not capped at 100 percent, so that the GUI layer displays capacity use without repeating the arithmetic.

### Requirement 6: Capacity Enforcement Before Writing

**User Story:** As a team member embedding a large payload, I want an oversized payload rejected before any file is written, so that no partial or misleading output file is produced.

#### Acceptance Criteria

1. WHEN THE Image_Stego_Module receives an embedding request, THE Image_Stego_Module SHALL obtain the available Capacity in bytes from THE Capacity_Calculator for the supplied Cover_Object, LSB_Depth, and Start_Location, derive the required Encoded_Stream length as the 4-byte Length_Header plus the Payload byte count, and compare the required length against the available Capacity before modifying any Embeddable_Byte and before creating, truncating, or opening for writing any file at the output path.
2. IF the required Encoded_Stream length is greater than the available Capacity, THEN THE Image_Stego_Module SHALL raise a capacity error that reports the required byte count and the available byte count, SHALL modify no Embeddable_Byte, and SHALL create no file at the output path.
3. WHEN the required Encoded_Stream length is less than or equal to the available Capacity, including the boundary case where the required length equals the available Capacity exactly, THE Image_Stego_Module SHALL raise no capacity error and SHALL produce a complete Stego_Object at the output path (capacity soundness property).
4. IF the required Encoded_Stream length exceeds the available Capacity by 1 byte or more, THEN THE Image_Stego_Module SHALL raise a capacity error and the output path SHALL remain absent, or, where a file already existed at that path, SHALL remain byte-identical to its pre-request content (capacity soundness property).
5. WHILE producing a Stego_Object, THE Image_Stego_Module SHALL write the complete Byte_Stream to a temporary file in the same directory as the output path and SHALL make the result visible at the output path only through a single replace operation, such that any concurrent reader of the output path observes either the pre-request content or the complete Stego_Object and never a partial Byte_Stream.
6. IF a file already exists at the output path and the embedding request does not enable overwrite, THEN THE Image_Stego_Module SHALL raise an error indicating that the output path is already occupied, SHALL modify no Embeddable_Byte, SHALL create no temporary file, and SHALL leave the existing file byte-identical to its pre-request content.
7. IF any error occurs after the temporary file is created and before the replace operation completes, THEN THE Image_Stego_Module SHALL delete the temporary file before propagating the error, SHALL leave no file at the output path other than any pre-existing file with its pre-request content unchanged, and SHALL propagate an error indicating the cause of the failure.
8. IF the replace operation fails on 3 consecutive attempts spaced at least 100 milliseconds apart because the operating system prevents replacement of the existing file at the output path, THEN THE Image_Stego_Module SHALL delete the temporary file, SHALL leave the existing file byte-identical to its pre-request content, and SHALL raise an error indicating that the output path could not be replaced.

### Requirement 7: Start Location Validation

**User Story:** As a team member using a derived start location, I want the supplied index validated against the image and the payload size, so that out-of-range values fail with a clear message instead of producing a corrupt stego image.

#### Acceptance Criteria

1. WHEN a caller supplies a Start_Location that is an integer from 0 to the total Embeddable_Byte count minus 1 inclusive, THE Image_Stego_Module SHALL accept the Start_Location and proceed to the Capacity comparison of Requirement 6, where the total Embeddable_Byte count equals width multiplied by height multiplied by embeddable channel count.
2. IF the supplied Start_Location is an integer less than 0 or greater than or equal to the total Embeddable_Byte count, THEN THE Image_Stego_Module SHALL raise a validation error that reports the supplied value and the valid range from 0 to the total Embeddable_Byte count minus 1 inclusive, and SHALL create no output file.
3. IF the count of Embeddable_Byte positions at or after the Start_Location is less than the required position count, being the ceiling of the Encoded_Stream length in bytes multiplied by 8 and divided by the LSB_Depth, THEN THE Image_Stego_Module SHALL raise a capacity error that reports the required position count and the available position count before modifying any sample, and SHALL create no output file.
4. THE Capacity_Calculator SHALL compute the highest valid Start_Location for a given Encoded_Stream length and a given LSB_Depth as the total Embeddable_Byte count minus the ceiling of the Encoded_Stream length in bytes multiplied by 8 and divided by the LSB_Depth, and SHALL report the valid range as 0 to that value inclusive, so that the cryptography layer derives Start_Location values within a valid range.
5. THE Image_Stego_Module SHALL apply the same Start_Location type check and range check during extraction as during embedding, using the total Embeddable_Byte count of the supplied image.
6. IF the supplied Start_Location is not an integer value, including a boolean value, a floating-point value whose fractional part is zero, a string value, and an absent value, THEN THE Image_Stego_Module SHALL raise a validation error that reports the supplied type, before performing any range comparison.
7. IF the required position count for the given Encoded_Stream length and LSB_Depth exceeds the total Embeddable_Byte count, THEN THE Capacity_Calculator SHALL return a result that reports the valid Start_Location range as empty together with the required position count and the total Embeddable_Byte count, and SHALL raise no error, so that the cryptography layer detects the empty range before attempting derivation.
8. THE Image_Stego_Module SHALL document that a non-zero Start_Location conceals the payload position only, provides no confidentiality and no authenticity, and that derivation of the Start_Location from a secret key is performed by the cryptography layer and not by this layer.

### Requirement 8: Image Quality Comparison

**User Story:** As a team member demonstrating the distortion trade-off, I want measured quality metrics between cover and stego images, so that the effect of LSB depth is shown with numbers rather than assertions.

#### Acceptance Criteria

1. WHEN a caller supplies two images with identical dimensions and channel count, THE Image_Analysis_Module SHALL return the overall MSE, the per-channel MSE, the overall PSNR in decibels, and the per-channel PSNR in decibels, where MSE is the mean of the squared per-sample differences computed after widening both sample arrays to a signed integer or floating-point numeric type of at least 32 bits, PSNR is 10 multiplied by the base-10 logarithm of 255 squared divided by MSE, and each returned metric is a double-precision floating-point value that THE Image_Analysis_Module does not round.
2. THE Image_Analysis_Module SHALL return a pixel-equality flag that is true exactly when every sample of the two images is equal including alpha samples where present, the maximum absolute per-sample difference as an integer from 0 to 255 inclusive, the count of differing samples, and the proportion of differing samples relative to the total sample count.
3. THE Image_Analysis_Module SHALL return the width, height, and channel count of each supplied image, and a flag for each of those three properties indicating equality.
4. IF the two supplied images differ in dimensions or channel count, THEN THE Image_Analysis_Module SHALL raise a comparison error reporting the height, width, and channel count of both images, SHALL return no metrics, and SHALL leave both supplied inputs unmodified.
5. FOR ALL pairs of pixel-identical images, the reported overall and per-channel MSE SHALL equal 0 and the reported overall and per-channel PSNR SHALL be the floating-point positive-infinity value accompanied by a boolean indicator that the PSNR is unbounded, so that a caller renders the value without parsing text (metric correctness property).
6. FOR ALL pairs of images that are not pixel-identical, the reported overall MSE SHALL be greater than 0 and the reported overall PSNR SHALL be a finite value, and FOR ALL individual channels whose samples are identical the reported per-channel MSE SHALL equal 0 and the reported per-channel PSNR SHALL carry the unbounded indicator (metric correctness property).
7. FOR ALL pairs of comparable images, exchanging the two arguments SHALL produce identical overall MSE, per-channel MSE, overall PSNR, per-channel PSNR, maximum absolute difference, and differing-sample counts (metric symmetry property).
8. FOR ALL fixed combinations of Cover_Object, Payload, and Start_Location in which the Payload length is at least 1024 bytes and the Encoded_Stream fits the available Capacity at LSB_Depth 1, and FOR ALL n from 1 to 7 inclusive, the overall PSNR between Cover_Object and Stego_Object at LSB_Depth n plus 1 SHALL not exceed the overall PSNR at LSB_Depth n by more than a tolerance of 0.5 decibels, and comparisons in which either PSNR carries the unbounded indicator SHALL be excluded (metamorphic property).
9. WHERE either supplied image has an alpha channel, THE Image_Analysis_Module SHALL exclude alpha samples from the overall MSE and the overall PSNR, consistent with the exclusion of alpha samples from the Embeddable_Byte definition, and SHALL report the alpha-channel MSE and PSNR as separately labelled per-channel values.
10. WHERE the caller supplies a file path for each of the two images, THE Image_Analysis_Module SHALL return the file size in bytes of each file and a flag indicating file-size equality.
11. THE Image_Analysis_Module SHALL return no cryptographic digest of either supplied image, and SHALL report the pixel-equality flag together with the differing-sample counts as this layer's sample-level equality evidence, because the file digest listed in the team media-comparison reference is produced by the cryptography layer.

### Requirement 9: Bit-Plane Visualisation

**User Story:** As a team member explaining LSB steganography, I want any bit plane of any channel exported as a viewable image, so that the visual effect of embedding on low-order planes is demonstrable.

#### Acceptance Criteria

1. WHEN a caller requests bit plane n of channel c, where n is an integer from 0 to 7 inclusive and c is an integer from 0 to the decoded channel count minus 1 inclusive, THE Image_Analysis_Module SHALL return a single-channel unsigned 8-bit array of the same height and width as the supplied image, in the same row-major orientation as the supplied image, in which each element holds the value of bit position n of the corresponding sample of channel c.
2. WHERE the caller requests no display scaling, THE Image_Analysis_Module SHALL restrict the returned Bit_Plane element values to 0 and 1.
3. WHERE the caller requests display scaling, THE Image_Analysis_Module SHALL return the Bit_Plane as an unsigned 8-bit array with bit value 0 mapped to sample value 0 and bit value 1 mapped to sample value 255, and SHALL leave the height, width, and element ordering identical to the unscaled Bit_Plane.
4. IF the requested bit position is not an integer from 0 to 7 inclusive, THEN THE Image_Analysis_Module SHALL raise a validation error reporting the supplied position and the valid range of 0 to 7 inclusive, and SHALL return no array.
5. IF the requested channel index is not an integer from 0 to the decoded channel count minus 1 inclusive, THEN THE Image_Analysis_Module SHALL raise a validation error reporting the supplied index and the decoded channel count, and SHALL return no array.
6. WHERE the supplied image has an alpha channel, THE Image_Analysis_Module SHALL accept the alpha channel index as a valid channel index for Bit_Plane extraction, independently of the exclusion of alpha-channel samples from the Byte_Stream stated in Requirement 2.
7. WHEN a caller requests every Bit_Plane of the supplied image in a single call, THE Image_Analysis_Module SHALL return the decoded channel count multiplied by 8 Bit_Plane arrays, each labelled with its channel index and bit position, ordered by ascending channel index and then ascending bit position, and SHALL apply the requested scaling mode to every returned Bit_Plane.
8. FOR ALL Bit_Plane requests, two invocations with identical image samples, channel index, bit position, and scaling mode SHALL return equal arrays, and the sample array supplied by the caller SHALL be equal before and after the call (determinism and input immutability properties).
9. THE Image_Analysis_Module SHALL return Bit_Plane data as arrays only, and SHALL write no image file, create no plot, and create no GUI object.

### Requirement 10: Difference Imaging

**User Story:** As a team member showing where an image changed, I want a visual difference image and a changed-sample count, so that the extent and location of embedding are visible.

#### Acceptance Criteria

1. WHEN a caller supplies two images with identical dimensions and channel count, THE Image_Analysis_Module SHALL widen both sample arrays to a numeric type of more than 8 bits before subtraction, so that no unsigned 8-bit wraparound occurs, and SHALL return a Difference_Image as an unsigned 8-bit array of the same height, width, and channel count as the supplied images, in which each element holds the per-sample absolute difference in the range 0 to 255 inclusive.
2. WHERE the caller requests amplification, THE Image_Analysis_Module SHALL return an unsigned 8-bit Difference_Image in which each per-sample absolute difference is multiplied by 255 divided by the maximum observed absolute difference and rounded to the nearest integer, and SHALL return the maximum observed absolute difference and the applied scale factor alongside the Difference_Image.
3. IF the maximum observed absolute difference is 0 and amplification is requested, THEN THE Image_Analysis_Module SHALL return an all-zero unsigned 8-bit Difference_Image, SHALL perform no division, and SHALL report the applied scale factor as 1.
4. WHERE the caller requests binary-mask mode, THE Image_Analysis_Module SHALL return an unsigned 8-bit Difference_Image in which every sample whose absolute difference is 0 maps to sample value 0 and every sample whose absolute difference is greater than 0 maps to sample value 255.
5. IF the caller requests amplification and binary-mask mode in the same call, THEN THE Image_Analysis_Module SHALL raise a validation error reporting that the two modes are mutually exclusive, and SHALL return no Difference_Image.
6. WHERE the supplied images have an alpha channel, THE Image_Analysis_Module SHALL include the alpha-channel samples in the Difference_Image, in the differing-sample count, and in the changed-pixel map, independently of the exclusion of alpha-channel samples from the Byte_Stream stated in Requirement 2.
7. THE Image_Analysis_Module SHALL return the count of pixels in which at least one channel differs, the count of differing samples, the total sample count computed as height multiplied by width multiplied by channel count, and the proportion of differing samples relative to the total sample count as a value from 0.0 to 1.0 inclusive.
8. THE Image_Analysis_Module SHALL return a changed-pixel map as a boolean array of the same height and width as the supplied images, in which an element is true exactly when at least one channel of the corresponding pixel differs between the two images.
9. IF the two supplied images differ in dimensions or channel count, THEN THE Image_Analysis_Module SHALL raise a comparison error reporting both shapes, and SHALL return no Difference_Image, no counts, and no changed-pixel map.

### Requirement 11: Image Steganalysis Indicators

**User Story:** As a team member evaluating an image for hidden data, I want statistical indicators of LSB anomalies, so that suspicious images are flagged for further inspection with honest reporting of the limits.

#### Acceptance Criteria

1. WHEN a caller requests LSB distribution statistics for one supplied image, THE Image_Analysis_Module SHALL return, overall and per colour channel, the count of analysed samples, the count of analysed samples whose bit 0 value is 1, and that count divided by the count of analysed samples, where the analysed samples are the Embeddable_Byte values of the supplied image, alpha-channel samples are excluded, and no Cover_Object or other reference image is required.
2. WHEN a caller requests the bit-0 uniformity indicator for one supplied image, THE Image_Analysis_Module SHALL return, per colour channel, a chi-square statistic computed from the observed counts of analysed samples whose bit 0 value is 0 and whose bit 0 value is 1 against an expected count of half the analysed sample count in each of the two categories, SHALL report the degrees of freedom as 1, and SHALL label the statistic as a bit-0 uniformity test that is a different indicator from the pair-of-values chi-square test of criterion 9.
3. WHEN a caller supplies two images for histogram comparison, THE Image_Analysis_Module SHALL return, for each colour channel index present in both images, the 256-bin histogram of the analysed samples of each image, the bin-wise difference of the two histograms as counts, and the bin-wise difference of the two histograms as proportions of each image's analysed sample count, and SHALL report the list of channel indices compared and the analysed sample count of each image.
4. WHEN a caller requests the pair-of-values neighbour indicator for one supplied image, THE Image_Analysis_Module SHALL return, per colour channel, the count of examined sample pairs, the count of examined pairs whose two values differ only in bit 0, and that count divided by the count of examined sample pairs, where an examined pair is the samples of one colour channel at two horizontally adjacent pixel positions in the same image row in Traversal_Order, pairs spanning a row boundary are excluded, the examined pair count per channel therefore equals width minus 1 multiplied by height, and this pairing is distinct from the histogram bin pairing of criterion 9.
5. THE Image_Analysis_Module SHALL return each steganalysis result labelled with the indicator name, the scope of the result as overall or as a colour channel index, either the numeric indicator value or the insufficient-sample status of criterion 10, the count of analysed samples used, the region bounds used, and the degrees of freedom for indicators that report a chi-square statistic.
6. THE Image_Analysis_Module SHALL accompany each steganalysis result, including each threshold flag, with a statement that the indicator does not establish the presence or absence of embedded data.
7. THE Image_Analysis_Module SHALL report indicator values without returning a detection verdict, a confidence percentage, a probability of embedding, or any value expressing likelihood or ranking of embedding.
8. WHERE the caller supplies a threshold for an indicator, THE Image_Analysis_Module SHALL return a flag that is true exactly when the indicator value is greater than or equal to the supplied threshold, and SHALL record the supplied threshold and the greater-than-or-equal comparison direction in the result.
9. WHEN a caller requests the pair-of-values chi-square indicator for one supplied image, THE Image_Analysis_Module SHALL return, per colour channel, a chi-square statistic computed over the 128 histogram bin pairs formed by sample values 2k and 2k plus 1 for k from 0 to 127 inclusive, using the arithmetic mean of the two bin counts of a pair as the expected count for both bins of that pair, SHALL exclude from the statistic every bin pair whose expected count is less than 5, SHALL report the count of included bin pairs, the count of excluded bin pairs, and the degrees of freedom as the count of included bin pairs minus 1, and SHALL require no Cover_Object or other reference image.
10. IF, for a colour channel, the count of analysed samples is fewer than 256, or the count of included bin pairs is fewer than 2, or the count of examined sample pairs is 0, THEN THE Image_Analysis_Module SHALL return for that channel and for each affected indicator an insufficient-sample status together with the analysed sample count, the included bin pair count, and the examined sample pair count, SHALL return no numeric value and no threshold flag for that affected indicator, and SHALL raise no error.
11. WHERE the caller supplies a rectangular region of interest as zero-based left and top offsets with a width and a height, THE Image_Analysis_Module SHALL compute every indicator of this requirement from only the analysed samples inside that region, and SHALL report the region offsets and dimensions and the region analysed sample count with each result.

### Requirement 12: Analysis Layer Independence

**User Story:** As the team member integrating the GUI, I want the analysis functions free of GUI dependencies, so that the same functions are callable from the Steganalysis tab, from tests, and from scripts.

#### Acceptance Criteria

1. THE Image_Analysis_Module SHALL return metrics as values of Python built-in types, restricted to bool, int, float, str, tuple, list, and dict, SHALL return image data as numeric arrays, and SHALL return no value whose type is defined by a graphical user interface toolkit.
2. THE Image_Analysis_Module SHALL import no PySide6 module, no other graphical user interface toolkit module, and no plotting module that requires an interactive display backend, and SHALL create no window, no widget, and no event loop.
3. IF a caller invokes an Image_Analysis_Module function with no output path argument, THEN THE Image_Analysis_Module SHALL create no file, modify no file, and delete no file on the filesystem, and SHALL render no plot and open no display surface.
4. FOR ALL Image_Analysis_Module functions, every caller-supplied sample array SHALL be equal element by element to its pre-call value after the call returns, and every returned array SHALL be a newly allocated array that shares no memory with any caller-supplied array, so that modifying a returned array changes no caller-supplied array (input immutability property).
5. FOR ALL Image_Analysis_Module functions, two invocations with identical inputs, whether in the same process or in separate processes, SHALL return results that are equal element by element for array results and exactly equal with no tolerance for numeric results (determinism property).
6. WHEN a caller supplies an image input to an Image_Analysis_Module function as either a filesystem path with a `.png` or `.bmp` extension or an already decoded sample array, THE Image_Analysis_Module SHALL accept both input forms and SHALL return results that are equal for the two forms whenever the file decodes to the supplied sample array (input-form equivalence property).
7. WHERE the caller supplies an explicit output path to an Image_Analysis_Module function, THE Image_Analysis_Module SHALL write exactly one file at that path and SHALL create or modify no other file.
8. WHILE up to 8 Image_Analysis_Module function invocations execute concurrently in separate threads of one process, including threads other than the process main thread, THE Image_Analysis_Module SHALL return for each invocation a result equal to the result that the same invocation returns when executed alone, and SHALL retain no mutable module-level state between invocations (thread-safety property).

### Requirement 13: Shared Bit and Capacity Helpers

**User Story:** As the team member implementing audio steganography, I want the bit manipulation and capacity arithmetic available as shared helpers, so that the audio module reuses one tested implementation.

#### Acceptance Criteria

1. THE Bit_Utils component SHALL provide a function converting a byte sequence of 0 to 67108864 bytes to a bit sequence in most-significant-bit-first order, producing exactly 8 bit values for each supplied byte.
2. THE Bit_Utils component SHALL provide a function converting a bit sequence whose length is an exact multiple of 8 to a byte sequence of one eighth that length, taking each consecutive group of 8 bit values as one byte in most-significant-bit-first order.
3. FOR ALL byte sequences of length 0 to 67108864 bytes, converting to a bit sequence and back to a byte sequence SHALL return a byte sequence equal to the original (round-trip property).
4. THE Bit_Utils component SHALL provide functions writing and reading the LSB_Depth lowest-order bits of an unsigned integer sample whose width is 8 bits or 16 bits, for LSB_Depth values from 1 to 8 inclusive, with the sample width supplied by the caller, so that the audio layer applies the same helpers to 16-bit PCM samples.
5. FOR ALL unsigned cover sample values of 8-bit width and of 16-bit width, FOR ALL LSB_Depth values from 1 to 8 inclusive, and FOR ALL data values from 0 to 2 raised to the power of the LSB_Depth minus 1, writing the data value and then reading the LSB_Depth lowest-order bits SHALL return the data value, and every bit position at or above the LSB_Depth SHALL equal its value before the write (round-trip and preservation property).
6. THE Bit_Utils component and THE Capacity_Calculator SHALL accept and return only integers, integer arrays, and byte sequences, and SHALL perform no file reading, no file writing, and no image or audio decoding.
7. THE Image_Stego_Module SHALL perform every byte-to-bit conversion, bit-to-byte conversion, and low-order-bit write and read operation by calling THE Bit_Utils component, and SHALL contain no separate bit-masking or bit-shifting implementation of those operations.
8. THE Bit_Utils component SHALL represent bit sequences as arrays of unsigned 8-bit values in which every element is 0 or 1, and SHALL complete each conversion, write, and read operation on a sequence of 36000000 elements in 5 seconds or less by operating on whole arrays rather than iterating element by element in Python.
9. IF the bit sequence supplied to the bit-to-byte conversion function has a length that is not an exact multiple of 8, THEN THE Bit_Utils component SHALL raise a validation error reporting the supplied bit count and the nearest multiple of 8, and SHALL return no byte sequence, so that padding remains the responsibility of the calling layer.
10. IF the supplied sample width is neither 8 nor 16 bits, or the supplied LSB_Depth is not an integer from 1 to 8 inclusive, THEN THE Bit_Utils component SHALL raise a validation error reporting the supplied value and the accepted values, and SHALL modify no supplied sample.

### Requirement 14: Error Handling and Input Validation

**User Story:** As a team member calling this layer, I want invalid inputs reported with specific and actionable errors, so that failures are diagnosable without reading the implementation.

#### Acceptance Criteria

1. IF the supplied input path does not exist, THEN THE Image_Stego_Module SHALL raise a file error that reports the file name component of the supplied path and states that the path was not found, and SHALL create no output file.
2. IF the supplied input path exists and is readable but the content cannot be decoded as an 8-bit-per-channel grayscale, RGB, or RGBA PNG or BMP image, THEN THE Image_Stego_Module SHALL raise a decode error that reports the file name component of the supplied path and the detected format where a format is detected, and SHALL create no output file.
3. IF the supplied LSB_Depth is not an integer value, or is a boolean value, or is an integer outside 1 to 8 inclusive, THEN THE Image_Stego_Module SHALL raise a validation error that reports the supplied value and the valid range of 1 to 8 inclusive.
4. IF the supplied Payload is not an instance of `bytes` or `bytearray`, THEN THE Image_Stego_Module SHALL raise a validation error that reports the type name of the supplied value and the accepted types.
5. IF the output directory does not exist, or exists but does not permit file creation by the calling process, THEN THE Image_Stego_Module SHALL raise a file error before decoding the Cover_Object and before modifying any sample, and SHALL create no output file.
6. WHEN a caller invokes embedding, THE Image_Stego_Module SHALL evaluate the checks in the order input path existence, input path readability, output path writability, Payload type, LSB_Depth, Start_Location, then Capacity, and SHALL raise only the error belonging to the first check that fails.
7. THE Image_Stego_Module SHALL raise exactly five distinct exception types, one each for file errors, decode errors, validation errors, capacity errors, and extraction errors, and SHALL define each of the five as a direct subclass of a single common base exception type of this layer, so that a caller catches one named category or every category of this layer with one handler.
8. IF the supplied input path exists but the calling process cannot open the file for reading, THEN THE Image_Stego_Module SHALL raise a file error of the same type as criterion 1 whose message distinguishes denied read access from a missing path, reporting the file name component of the supplied path, and SHALL create no output file.
9. THE Image_Stego_Module SHALL attach to every raised error a message of at least 1 and at most 500 characters that names the failed check and reports the offending value, and SHALL exclude the directory portion of any filesystem path from that message.
10. WHEN a caller invokes extraction, THE Image_Stego_Module SHALL evaluate the checks in the order input path existence, input path readability, decodability, LSB_Depth, then Start_Location, SHALL raise only the error belonging to the first check that fails, and SHALL leave the input file unmodified.

### Requirement 15: Correctness Properties for Automated Testing

**User Story:** As a team member maintaining this layer, I want the core correctness properties written as executable property tests, so that regressions in embedding, extraction, and metrics are caught automatically.

#### Acceptance Criteria

1. FOR ALL generated images with width from 1 to 64 pixels inclusive, height from 1 to 64 pixels inclusive, channel count of 1, 3, or 4, and 8-bit samples, FOR ALL LSB_Depth values from 1 to 8 inclusive, FOR ALL Start_Location values from 0 to the total Embeddable_Byte count minus 1 inclusive, and FOR ALL Payload values of length 0 to 256 bytes inclusive whose Encoded_Stream fits the available Capacity, `extract_image` applied to the output of `embed_image` SHALL return a byte sequence equal to the Payload (round-trip property).
2. FOR ALL generated images, LSB_Depth values, Start_Location values, and Payload lengths within the generation bounds of criterion 1, embedding a Payload whose Encoded_Stream length is less than or equal to the reported available Capacity SHALL write an output file, and embedding a Payload whose Encoded_Stream length exceeds the reported available Capacity by 1 byte or more SHALL raise a capacity error and SHALL leave no file at the output path (capacity soundness property).
3. FOR ALL successful embeddings within the generation bounds of criterion 1, the Stego_Object sample array SHALL equal the Cover_Object sample array at every bit position at or above the LSB_Depth, at every Embeddable_Byte position outside the written index range, and at every alpha-channel sample (cover preservation property).
4. FOR ALL successful embeddings within the generation bounds of criterion 1, the per-sample absolute difference between the Stego_Object and the Cover_Object SHALL be less than 2 raised to the power of the LSB_Depth, and FOR ALL fixed combinations of Cover_Object, Payload, and Start_Location the PSNR SHALL be non-increasing as the LSB_Depth increases from 1 to 8 (bounded distortion property).
5. FOR ALL image pairs of identical dimensions and channel count generated within the bounds of criterion 1, the reported MSE SHALL equal 0 and the reported PSNR SHALL be positive infinity if and only if the pair is pixel-identical, and exchanging the two arguments SHALL return MSE and PSNR values equal to those returned for the original argument order (metric correctness property).
6. FOR ALL identical combinations of Cover_Object, Payload, LSB_Depth, and Start_Location within the generation bounds of criterion 1, two successive embedding operations SHALL produce byte-identical Stego_Object sample data (determinism property).
7. FOR ALL Image_Analysis_Module calls with arrays generated within the bounds of criterion 1, every supplied input array SHALL be element-by-element equal to a copy taken before the call (input immutability property).
8. THE test suite SHALL include example-based boundary and error-condition tests for a truncated bit stream, a garbage bit stream, a lossy format input, a palette format input, LSB_Depth values of 0 and 9, Start_Location values of -1 and of the total Embeddable_Byte count, a Payload of length 0, a Payload whose Encoded_Stream length equals the available Capacity exactly, and a Payload whose Encoded_Stream length exceeds the available Capacity by exactly 1 byte, and SHALL assert the specific exception type of this layer for each case expected to fail.
9. THE test suite SHALL use one or two representative example tests, rather than property tests, for file format handling of specific PNG and BMP sample files.
10. THE property-based test suite SHALL generate at most 100 examples per property and SHALL apply either no per-example time limit or a per-example time limit of at least 1000 milliseconds, and the complete property-based suite SHALL finish within 120 seconds of wall-clock time.
11. WHEN a test writes a Cover_Object file or a Stego_Object file, THE test suite SHALL write that file inside a temporary directory created for that test and SHALL leave no generated file or temporary directory in place after the test session ends.
12. IF a property test fails, THEN THE test suite SHALL report the generated image width, height, channel count, LSB_Depth, Start_Location, and Payload length of the failing example, so that the failure is reproducible without rerunning generation.
