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

// Function to count the number of ones in a code
static int ones_in_code(uint32_t code, int size)
{
    int count = 0;
    for (int i = 0; i < size; i++)
    {
        if ((code >> i) & 1)
        {
            count++;
        }
    }
    return count;
}

// Initialize the Golay encoding lookup table
static void InitGolayEncode(void)
{
    for (uint32_t x = 0; x < GOLAY_SIZE; x++)
    {
        uint32_t code = x << 12;
        for (int i = 0; i < 12; i++)
        {
            if ((x >> (11 - i)) & 1)
            {
                code ^= G_P[i];
            }
        }
        EncodeTable[x] = code;
    }
}

// Initialize the Golay decoding lookup tables
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
    {
        for (int j = 0; j < 24; j++)
        {
            for (int k = 0; k < 24; k++)
            {
                uint32_t error = (1 << i) | (1 << j) | (1 << k);
                uint16_t syndrome = SyndromeTable[(error >> 12) & 0x0FFF] ^ (error & 0x0FFF);
                CorrectTable[syndrome] = (error >> 12) & 0x0FFF;
                ErrorTable[syndrome] = ones_in_code(error, 24);
            }
        }
    }
}

// Python wrapper for golay_init_tables
static PyObject *py_golay_init_tables(PyObject *self, PyObject *args)
{
    InitGolayEncode();
    InitGolayDecode();
    Py_RETURN_NONE;
}

// Python wrapper for golay_encode
static PyObject *py_golay_encode(PyObject *self, PyObject *args)
{
    uint16_t raw;
    if (!PyArg_ParseTuple(args, "H", &raw))
    {
        return NULL;
    }
    if (raw > 0x0FFF)
    {
        PyErr_SetString(PyExc_ValueError, "Input must be a 12-bit unsigned integer.");
        return NULL;
    }
    uint32_t encoded = EncodeTable[raw & 0x0FFF];
    return PyLong_FromUnsignedLong(encoded);
}

// Python wrapper for golay_decode
static PyObject *py_golay_decode(PyObject *self, PyObject *args)
{
    PyObject *input;
    if (!PyArg_ParseTuple(args, "O", &input))
    {
        return NULL;
    }

    uint32_t encoded;

    // Handle bytes input (should be 3 bytes)
    if (PyBytes_Check(input))
    {
        if (PyBytes_Size(input) != 3)
        {
            PyErr_SetString(PyExc_ValueError, "3-byte input required");
            return NULL;
        }
        const unsigned char *buf = (const unsigned char *)PyBytes_AsString(input);
        // Convert big-endian bytes to 24-bit unsigned integer
        encoded = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
    }
    // Handle integer input
    else if (PyLong_Check(input))
    {
        encoded = PyLong_AsUnsignedLong(input);
        if (PyErr_Occurred())
        {
            return NULL; // Overflow or invalid conversion
        }
        if (encoded > 0xFFFFFF)
        {
            PyErr_SetString(PyExc_ValueError, "Input must be a 24-bit unsigned integer.");
            return NULL;
        }
    }
    else
    {
        PyErr_SetString(PyExc_TypeError, "Expected a 3-byte bytes object or 24-bit integer.");
        return NULL;
    }

    // Decode logic
    uint16_t v1 = (encoded >> 12) & 0x0FFF;
    uint16_t v2 = encoded & 0x0FFF;
    uint16_t syndrome = SyndromeTable[v2] ^ v1;
    uint16_t corrected = v1 ^ CorrectTable[syndrome];

    return PyLong_FromUnsignedLong(corrected);
}

static PyObject *py_golay_errors(PyObject *self, PyObject *args)
{
    uint32_t v;
    if (!PyArg_ParseTuple(args, "I", &v))
    {
        return NULL;
    }
    if (v > 0xFFFFFF)
    {
        PyErr_SetString(PyExc_ValueError, "Input must be a 24-bit unsigned integer.");
        return NULL;
    }

    uint16_t v1 = (v >> 12) & 0x0FFF;
    uint16_t v2 = v & 0x0FFF;
    uint16_t syndrome = SyndromeTable[v2] ^ v1;
    uint8_t errors = ErrorTable[syndrome];
    return PyLong_FromUnsignedLong(errors);
}

// Module method definitions
static PyMethodDef GolayMethods[] = {
    {"golay_init_tables", py_golay_init_tables, METH_NOARGS, "Initialize Golay encoding and decoding tables."},
    {"golay_encode", py_golay_encode, METH_VARARGS, "Encode a 12-bit value using Golay code."},
    {"golay_decode", py_golay_decode, METH_VARARGS, "Decode a 24-bit Golay codeword."},
    {"golay_errors", py_golay_errors, METH_VARARGS, "Get the number of bit errors in a 24-bit Golay codeword."},
    {NULL, NULL, 0, NULL}};

// Module definition
static struct PyModuleDef golay_c_module = {
    PyModuleDef_HEAD_INIT,
    "golay_c",
    "C extension module for Golay encoding and decoding.",
    -1,
    GolayMethods};

// Module initialization function
PyMODINIT_FUNC PyInit_golay_c(void)
{
    return PyModule_Create(&golay_c_module);
}
