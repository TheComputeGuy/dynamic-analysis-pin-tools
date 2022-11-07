/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include "pin.h"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
using std::hex;

ofstream OutFile;
bool entryFlag = false;
ADDRINT entryPoint;
ADDRINT imageLowAddress;
ADDRINT imageHighAddress;
string greencat = "webc2-greencat-2";

// make this static to help the compiler optimize our analysis function
static UINT32 prevIP = 0;
static std::map<UINT32, std::set<UINT32>> edgeMap;
static std::set<UINT32> edgeSet;

// This function is called before every instruction is executed
VOID docount(UINT32 ip) {
    ip = ip - imageLowAddress;
    if (prevIP != ip) {
        auto search = edgeMap.find(prevIP);
        if (search != edgeMap.end()) {
            search->second.insert(ip);
        }
        else {
            std::set<ADDRINT> edgeSetLocal;
            edgeSetLocal.insert(ip);
            edgeMap[prevIP] = edgeSetLocal;
        }
        prevIP = ip;
    }
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v)
{
    ADDRINT instAddress = INS_Address(ins);

    if (instAddress == entryPoint) {
        entryFlag = true;
    }
    if (entryFlag) {
        if (instAddress >= imageLowAddress && instAddress <= imageHighAddress) {
            // Insert a call to docount on every instruction after entrypoint is passed, 
            // instruction pointer is passed as argument
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_INST_PTR, IARG_END);
        }
    }
}

VOID Image(IMG img, VOID* v) {
    string imageName = IMG_Name(img);

    // Instrument only functions inside greencat binary
    if (imageName.find(greencat) != string::npos) {
        imageLowAddress = IMG_LowAddress(img);
        imageHighAddress = IMG_HighAddress(img);
        entryPoint = IMG_EntryAddress(img);

        // Register Instruction to be called to instrument instructions
        INS_AddInstrumentFunction(Instruction, 0);
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile << "digraph {\n";
    for (auto& edgesFrom : edgeMap) {
        for (auto& edgeTo : edgesFrom.second) {
            OutFile << "\""  << hex << edgesFrom.first << "\" -> \"" << hex << edgeTo << "\"\n";
        }
    }
    OutFile << "}";
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());
    OutFile.setf(ios::showbase);

    // Register Image to be called to instrument the image - to get address of WinMain
    IMG_AddInstrumentFunction(Image, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}