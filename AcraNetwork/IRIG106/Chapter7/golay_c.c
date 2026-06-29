#include <Python.h>
#include <stdint.h>

#define GOLAY_SIZE 0x1000

// Generator matrix: parity sub-generator matrix P
static const uint16_t G_P[12] = {
    0x0C75, 0x063B, 0x0F68, 0x07B4,
    0x03DA, 0x0D99, 0x06CD, 0x0367,
    0x0DC6, 0x0A97, 0x093E, 0x08EB};

// Parity-check matrix H_P
static const uint16_t H_P[12] = {
    0x0A4F, 0x0F68, 0x07B4, 0x03DA,
    0x01ED, 0x0AB9, 0x0F13, 0x0DC6,
    0x06E3, 0x093E, 0x049F, 0x0C75};

// Lookup tables
static uint32_t EncodeTable[GOLAY_SIZE];
static uint16_t SyndromeTable[GOLAY_SIZE];
static uint32_t CorrectTable[GOLAY_SIZE];
static uint8_t ErrorTable[GOLAY_SIZE];

// ------------------------------------------------------------------ //
//  Internal C-only Golay helpers — not exposed to Python              //
// ------------------------------------------------------------------ //

static int ones_in_code(uint32_t code, int size)
{
    int count = 0;
    for (int i = 0; i < size; i++)
    {
        if ((code >> i) & 1)
            count++;
    }
    return count;
}

static void InitGolayEncode(void)
{
    for (uint32_t x = 0; x < GOLAY_SIZE; x++)
    {
        uint32_t code = x << 12;
        for (int i = 0; i < 12; i++)
        {
            if ((x >> (11 - i)) & 1)
                code ^= G_P[i];
        }
        EncodeTable[x] = code;
    }
}

static void InitGolayDecode(void)
{
    for (uint32_t x = 0; x < GOLAY_SIZE; x++)
    {
        SyndromeTable[x] = 0;
        for (int i = 0; i < 12; i++)
        {
            if ((x >> (11 - i)) & 1)
            {
                SyndromeTable[x] ^= H_P[i];
                ErrorTable[x] = 4;
                CorrectTable[x] = 0x0FFF;
            }
        }
    }

    ErrorTable[0] = 0;
    CorrectTable[0] = 0;

    for (int i = 0; i < 24; i++)
        for (int j = 0; j < 24; j++)
            for (int k = 0; k < 24; k++)
            {
                uint32_t error = (1 << i) | (1 << j) | (1 << k);
                uint16_t syndrome = SyndromeTable[error & 0x0FFF] ^ ((error >> 12) & 0x0FFF);
                CorrectTable[syndrome] = (error >> 12) & 0x0FFF;
                ErrorTable[syndrome] = ones_in_code(error, 24);
            }
}

/*
 * golay_decode_raw — decode 3 bytes (big-endian) directly from a buffer.
 * Pure C, no Python overhead. Used internally by ptdp_unpack / ptfr_unpack.
 */
static inline uint16_t golay_decode_raw(const unsigned char *buf)
{
    uint32_t encoded = ((uint32_t)buf[0] << 16)
                     | ((uint32_t)buf[1] <<  8)
                     |  (uint32_t)buf[2];
    uint16_t v1 = (encoded >> 12) & 0x0FFF;
    uint16_t v2 =  encoded        & 0x0FFF;
    uint16_t syndrome = SyndromeTable[v2] ^ v1;
    return v1 ^ CorrectTable[syndrome];
}

// ------------------------------------------------------------------ //
//  Python-visible Golay functions (unchanged from original)           //
// ------------------------------------------------------------------ //

static PyObject *py_golay_init_tables(PyObject *self, PyObject *args)
{
    InitGolayEncode();
    InitGolayDecode();
    Py_RETURN_NONE;
}

static PyObject *py_golay_encode(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"raw", "as_string", NULL};
    uint16_t raw;
    int as_string = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "H|p", kwlist, &raw, &as_string))
        return NULL;

    if (raw > 0x0FFF)
    {
        PyErr_SetString(PyExc_ValueError, "Only 12-bit unsigned values allowed");
        return NULL;
    }

    uint32_t encoded = EncodeTable[raw & 0x0FFF];

    if (as_string)
    {
        unsigned char buf[3] = {
            (encoded >> 16) & 0xFF,
            (encoded >>  8) & 0xFF,
             encoded        & 0xFF
        };
        return PyBytes_FromStringAndSize((char *)buf, 3);
    }
    return PyLong_FromUnsignedLong(encoded);
}

static PyObject *py_golay_decode(PyObject *self, PyObject *args)
{
    PyObject *input;
    if (!PyArg_ParseTuple(args, "O", &input))
        return NULL;

    uint32_t encoded;

    if (PyObject_CheckBuffer(input))
    {
        Py_buffer view;
        if (PyObject_GetBuffer(input, &view, PyBUF_SIMPLE) != 0)
            return NULL;
        if (view.len != 3)
        {
            PyBuffer_Release(&view);
            PyErr_SetString(PyExc_ValueError, "3-byte input required");
            return NULL;
        }
        const unsigned char *buf = (const unsigned char *)view.buf;
        encoded = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
        PyBuffer_Release(&view);
    }
    else if (PyLong_Check(input))
    {
        encoded = PyLong_AsUnsignedLong(input);
        if (PyErr_Occurred())
            return NULL;
        if (encoded > 0xFFFFFF)
        {
            PyErr_SetString(PyExc_ValueError, "Only 24-bit unsigned values supported");
            return NULL;
        }
    }
    else
    {
        PyErr_SetString(PyExc_TypeError, "Expected a bytes-like object (3 bytes) or 24-bit integer.");
        return NULL;
    }

    uint16_t v1 = (encoded >> 12) & 0x0FFF;
    uint16_t v2 =  encoded        & 0x0FFF;
    uint16_t syndrome = SyndromeTable[v2] ^ v1;
    return PyLong_FromUnsignedLong(v1 ^ CorrectTable[syndrome]);
}

static PyObject *py_golay_errors(PyObject *self, PyObject *args)
{
    uint32_t v;
    if (!PyArg_ParseTuple(args, "I", &v))
        return NULL;
    if (v > 0xFFFFFF)
    {
        PyErr_SetString(PyExc_ValueError, "Input must be a 24-bit unsigned integer.");
        return NULL;
    }

    uint16_t v1 = (v >> 12) & 0x0FFF;
    uint16_t v2 =  v        & 0x0FFF;
    uint16_t syndrome = SyndromeTable[v2] ^ v1;
    return PyLong_FromUnsignedLong(ErrorTable[syndrome]);
}

// ------------------------------------------------------------------ //
//  ptdp_unpack                                                        //
//                                                                     //
//  Mirrors PTDP.unpack() in Chapter7.py.                             //
//                                                                     //
//  Returns:                                                           //
//    None                      — buffer too short (< 6 bytes)        //
//    -1  (PyLong)              — PTDPLengthError (corrupt length)     //
//    (length, fragment,        — success                              //
//     content, remainder_start)                                       //
//                                                                     //
//  The Python wrapper still does:                                     //
//    self._payload = buffer[6 : 6+length]   (already C-speed)        //
//    return buffer[remainder_start:]         (already C-speed)        //
// ------------------------------------------------------------------ //

#define PTDP_HDR_LEN   6
#define PTDP_MAX_LEN   0x800

static PyObject *py_ptdp_unpack(PyObject *self, PyObject *args)
{
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view))
        return NULL;

    const unsigned char *buf = (const unsigned char *)view.buf;
    Py_ssize_t buf_len = view.len;
    PyBuffer_Release(&view);

    // Guard: need at least 6 bytes for the two Golay-encoded header words
    if (buf_len < PTDP_HDR_LEN)
        Py_RETURN_NONE;

    // Decode both header words — pure C, zero Python overhead
    uint16_t lsw = golay_decode_raw(buf);       // bytes 0-2
    uint16_t msw = golay_decode_raw(buf + 3);   // bytes 3-5

    // Reconstruct payload length from the two 12-bit Golay values
    int length = (int)msw + (((int)lsw & 0xF) << 12);

    // Sanity check — corrupt Golay data produces impossible lengths
    if (length > PTDP_MAX_LEN)
        return PyLong_FromLong(-1L);    // signals PTDPLengthError to Python

    // Check we have enough data for the full PTDP
    int remainder_start = length + PTDP_HDR_LEN;
    if (buf_len < remainder_start)
        Py_RETURN_NONE;

    // Extract fragment (bits 5:4 of lsw) and content (bits 9:6 of lsw)
    int fragment = ((int)lsw >> 4) & 0x3;
    int content  = ((int)lsw >> 6) & 0xF;

    return Py_BuildValue("(iiii)", length, fragment, content, remainder_start);
}

// ------------------------------------------------------------------ //
//  ptfr_unpack                                                        //
//                                                                     //
//  Mirrors PTFR.unpack() in Chapter7.py.                             //
//                                                                     //
//  Returns:                                                           //
//    None                           — buffer too short (< 4 bytes)   //
//    (version, streamid, llp,       — success                        //
//     ptdp_offset)                                                    //
//                                                                     //
//  The Python wrapper still does:                                     //
//    self.payload = buffer[4:]      (already C-speed)                //
// ------------------------------------------------------------------ //

#define PTFR_HDR_LEN   4

static PyObject *py_ptfr_unpack(PyObject *self, PyObject *args)
{
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view))
        return NULL;

    const unsigned char *buf = (const unsigned char *)view.buf;
    Py_ssize_t buf_len = view.len;
    PyBuffer_Release(&view);

    // Guard: need at least 4 bytes (1 unprotected + 3 Golay-protected)
    if (buf_len < PTFR_HDR_LEN)
        Py_RETURN_NONE;

    // First byte: version (bits 1:0) and stream ID (bits 7:4)
    unsigned char byte0 = buf[0];
    int version   =  byte0        & 0x3;
    int streamid  = (byte0 >> 4)  & 0xF;

    // Bytes 1-3: Golay-protected field containing LLP flag and PTDP offset
    uint16_t protected_field = golay_decode_raw(buf + 1);
    int llp         = (protected_field >> 11) & 0x1;
    int ptdp_offset =  protected_field        & 0x7FF;

    return Py_BuildValue("(iiii)", version, streamid, llp, ptdp_offset);
}

// ------------------------------------------------------------------ //
//  Module method table                                                //
// ------------------------------------------------------------------ //

static PyMethodDef GolayMethods[] = {
    {"golay_init_tables", py_golay_init_tables,
        METH_NOARGS,  "Initialize Golay encoding and decoding tables."},
    {"golay_encode",      (PyCFunction)py_golay_encode,
        METH_VARARGS | METH_KEYWORDS, "Encode a 12-bit value using Golay code."},
    {"golay_decode",      py_golay_decode,
        METH_VARARGS, "Decode a 24-bit Golay codeword."},
    {"golay_errors",      py_golay_errors,
        METH_VARARGS, "Get the number of bit errors in a 24-bit Golay codeword."},
    {"ptdp_unpack",       py_ptdp_unpack,
        METH_VARARGS, "Unpack a PTDP header from a buffer. Returns (length, fragment, content, remainder_start) or None or -1."},
    {"ptfr_unpack",       py_ptfr_unpack,
        METH_VARARGS, "Unpack a PTFR header from a buffer. Returns (version, streamid, llp, ptdp_offset) or None."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef golay_c_module = {
    PyModuleDef_HEAD_INIT,
    "golay_c",
    "C extension module for Golay encoding, decoding, and Chapter7 unpacking.",
    -1,
    GolayMethods
};

PyMODINIT_FUNC PyInit_golay_c(void)
{
    return PyModule_Create(&golay_c_module);
}