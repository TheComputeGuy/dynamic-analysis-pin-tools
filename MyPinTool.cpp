/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include "pin.h"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
using std::map;
using std::set;
using std::vector;
using std::hex;

ofstream OutFile;
ofstream TraceFile;
ofstream BranchFile;
bool entryFlag = false;
ADDRINT entryPoint;
ADDRINT imageLowAddress;
ADDRINT imageHighAddress;
string greencat = "webc2-greencat-2";

// make this static to help the compiler optimize our analysis function
static UINT32 prevIP = 0;
static map<UINT32, set<UINT32>> edgeMap;
static set<UINT32> edgeSet;
static vector<UINT32> trace;
static set<UINT32> branches;

// This function is called before every instruction is executed
VOID analyse(UINT32 ip, bool isConditionalBranch) {
    trace.push_back(prevIP);

    ip = ip - imageLowAddress;

    if (isConditionalBranch) {
        branches.insert(ip);
    }

    if (prevIP != ip) {
        auto search = edgeMap.find(prevIP);
        if (search != edgeMap.end()) {
            search->second.insert(ip);
        }
        else {
            set<ADDRINT> edgeSetLocal;
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
            // instruction pointer is passed as argument, 
            // along with whether it is conditional or not, for CDG analysis
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)analyse, IARG_INST_PTR, 
                IARG_BOOL, (INS_IsBranch(ins) && INS_HasFallThrough(ins)), IARG_END);
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

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "cfg.dot", "specify output file name");
KNOB< string > KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool", "t", "trace.txt", "specify trace file name");
KNOB< string > KnobBranchFile(KNOB_MODE_WRITEONCE, "pintool", "b", "branches.txt", "specify branch file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    // Writing to a file since cout and cerr maybe closed by the application
    // Write the CFG to a dotfile
    OutFile.setf(ios::showbase);
    OutFile << "digraph {\n";
    for (auto& edgesFrom : edgeMap) {
        for (auto& edgeTo : edgesFrom.second) {
            OutFile << "\""  << hex << edgesFrom.first << "\" -> \"" << hex << edgeTo << "\"\n";
        }
    }
    OutFile << "}";
    OutFile.close();

    // Write to trace file
    TraceFile.setf(ios::showbase);
    for (auto& instr : trace) {
        TraceFile << hex << instr << "\n";
    }
    TraceFile.close();

    // Write to branch file
    BranchFile.setf(ios::showbase);
    for (auto& instr : branches) {
        BranchFile << hex << instr << "\n";
    }
    BranchFile.close();
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
    TraceFile.open(KnobTraceFile.Value().c_str());
    BranchFile.open(KnobBranchFile.Value().c_str());

    // Register Image to be called to instrument the image - to get address of WinMain
    IMG_AddInstrumentFunction(Image, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}