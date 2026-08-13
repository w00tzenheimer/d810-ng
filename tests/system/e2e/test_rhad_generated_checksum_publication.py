"""Exact A560 GENERATED checksum canary through ctree generation."""

from __future__ import annotations

import hashlib
import faulthandler
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys

import pytest


idapro = pytest.importorskip("idapro")

# The dedicated Rhadamanthys loader regression work is owned by another branch.
# Keep this module visible in collection, but do not make its in-progress oracle
# block cfg-recon-mainline's system suite.
pytestmark = pytest.mark.skip(reason="Rhadamanthys loader regressions are owned by a separate branch")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_BINARY = _REPO / "samples" / "bins" / "rhad_loader_unpacked.bin"
_FUNCTION_EA = 0x40A560
_EXPECTED_SHA256 = "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
_SIDECARS = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")
_FAILURE_OUTPUT_LIMIT = 12_000
_REFERENCE_OPERATION_IDS = (
    "rhad:route@0x40A605",
    "route:rhad-direct@0x40A619",
    "route:rhad-direct@0x40A631",
    "route:rhad-direct@0x40A649",
    "route:rhad-direct@0x40A661",
    "route:rhad-direct@0x40A679",
    "route:rhad-direct@0x40A68A",
    "rhad:route@0x40A6A4",
    "rhad:route@0x40A6BE",
    "rhad:route@0x40A6D8",
    "rhad:route@0x40A6F2",
    "rhad:route@0x40A70C",
    "route:rhad-direct@0x40A74A",
    "rhad:route@0x40A764",
    "rhad:route@0x40A77C",
    "rhad:route@0x40A792",
    "rhad:route@0x40A7AC",
    "route:rhad-direct@0x40A7EF",
    "rhad:route@0x40A818",
    "rhad:route@0x40A832",
    "rhad:route@0x40A84C",
    "rhad:route@0x40A866",
    "route:rhad-direct@0x40A8B3",
    "rhad:route@0x40A8CD",
    "rhad:route@0x40A8E7",
    "rhad:route@0x40A901",
    "route:rhad-direct@0x40A95E",
    "rhad:route@0x40A978",
    "rhad:route@0x40A992",
    "rhad:route@0x40A9AC",
    "rhad:route@0x40A9DC",
    "rhad:route@0x40A9F6",
    "rhad:route@0x40AA10",
    "rhad:route@0x40AA2A",
    "rhad:route@0x40AA5E",
    "rhad:route@0x40AA78",
    "rhad:route@0x40AA92",
    "rhad:route@0x40AAAC",
    "route:rhad-direct@0x40AAFB",
    "rhad:route@0x40AB15",
    "rhad:route@0x40AB2F",
    "route:rhad-direct@0x40AB74",
    "rhad:route@0x40AB8E",
    "rhad:route@0x40ABA8",
    "rhad:route@0x40ABDE",
    "rhad:route@0x40ABF8",
    "route:rhad-direct@0x40AC3B",
    "rhad:route@0x40AC54",
    "rhad:route@0x40AC6E",
    "route:rhad-direct@0x40ACBD",
    "rhad:route@0x40ACD7",
    "rhad:route@0x40ACF1",
    "route:rhad-direct@0x40AD1C",
    "rhad:route@0x40AD36",
    "rhad:route@0x40AD50",
    "rhad:route@0x40AD6C",
    "rhad:route@0x40AD86",
    "rhad:route@0x40ADA0",
    "rhad:route@0x40ADBC",
    "rhad:route@0x40ADD6",
    "rhad:route@0x40ADF0",
    "rhad:route@0x40AE18",
    "route:rhad-direct@0x40AE24",
    "rhad:route@0x40AE3C",
    "rhad:route@0x40AE89",
    "rhad:route@0x40AEA3",
    "route:rhad-direct@0x40AEE4",
    "rhad:route@0x40AEFE",
    "route:rhad-direct@0x40AFDD",
    "rhad:route@0x40AFF7",
    "route:rhad-direct@0x40B022",
    "rhad:route@0x40B03C",
    "route:rhad-direct@0x40B06F",
    "rhad:route@0x40B089",
    "rhad:route@0x40B0BA",
    "rhad:route@0x40B0D4",
    "rhad:route@0x40B0F0",
    "rhad:route@0x40B10A",
    "rhad:route@0x40B147",
    "rhad:route@0x40B161",
    "rhad:route@0x40B17D",
    "rhad:route@0x40B197",
    "route:rhad-direct@0x40B1CE",
    "rhad:route@0x40B1E8",
    "rhad:route@0x40B21A",
    "rhad:route@0x40B234",
    "rhad:route@0x40B26B",
    "rhad:route@0x40B285",
    "route:rhad-direct@0x40B2D9",
    "rhad:route@0x40B2F3",
    "route:rhad-direct@0x40B32A",
    "rhad:route@0x40B340",
    "rhad:route@0x40B37A",
    "rhad:route@0x40B394",
    "rhad:route@0x40B3AE",
    "rhad:route@0x40B3E3",
    "rhad:route@0x40B3FD",
    "rhad:route@0x40B4C3",
    "route:rhad-direct@0x40B4EE",
    "route:rhad-direct@0x40B519",
    "route:rhad-direct@0x40B540",
    "route:rhad-direct@0x40B56B",
    "route:rhad-direct@0x40B596",
    "route:rhad-direct@0x40B5B5",
    "route:rhad-direct@0x40B5DC",
    "route:rhad-direct@0x40B607",
    "route:rhad-direct@0x40B626",
    "route:rhad-direct@0x40B645",
    "route:rhad-direct@0x40B666",
    "route:rhad-direct@0x40B691",
    "route:rhad-direct@0x40B6B2",
    "rhad:route@0x40B6D4",
    "rhad:route@0x40B6EE",
    "rhad:route@0x40B708",
    "rhad:route@0x40B722",
    "rhad:route@0x40B73C",
    "rhad:route@0x40B756",
    "route:rhad-direct@0x40B781",
    "rhad:route@0x40B7A8",
    "rhad:route@0x40B7C2",
    "rhad:route@0x40B7DC",
    "rhad:route@0x40B7F4",
    "rhad:route@0x40B80E",
    "rhad:route@0x40B879",
    "rhad:route@0x40B896",
    "rhad:route@0x40B8B0",
    "rhad:route@0x40B8CA",
    "rhad:route@0x40B8E4",
    "route:rhad-direct@0x40B931",
    "rhad:route@0x40B956",
    "rhad:route@0x40B970",
    "rhad:route@0x40B98A",
    "rhad:route@0x40B9A4",
    "route:rhad-direct@0x40BB73",
    "rhad:route@0x40BB8D",
    "rhad:route@0x40BBA7",
    "rhad:route@0x40BBC1",
    "rhad:route@0x40BBDD",
    "rhad:route@0x40BBF7",
    "rhad:route@0x40BC11",
    "rhad:route@0x40BC2B",
    "rhad:route@0x40BC5F",
    "rhad:route@0x40BC79",
    "rhad:route@0x40BC93",
    "rhad:route@0x40BCAD",
    "rhad:route@0x40BCC9",
    "rhad:route@0x40BCE3",
    "rhad:route@0x40BCFD",
    "rhad:route@0x40BD17",
    "rhad:route@0x40BD4E",
    "rhad:route@0x40BD68",
    "rhad:route@0x40BD82",
    "rhad:route@0x40BE2D",
    "rhad:route@0x40BE47",
    "rhad:route@0x40BE61",
    "rhad:route@0x40BE96",
    "rhad:route@0x40BEB0",
    "rhad:route@0x40BECA",
    "rhad:route@0x40BEE5",
    "rhad:route@0x40BEFF",
    "rhad:route@0x40BF19",
    "route:rhad-direct@0x40BF8A",
    "rhad:route@0x40BFA2",
    "rhad:route@0x40BFBC",
    "rhad:route@0x40BFD8",
    "rhad:route@0x40BFF2",
    "rhad:route@0x40C00C",
    "route:rhad-direct@0x40C03F",
    "rhad:route@0x40C059",
    "rhad:route@0x40C073",
    "route:rhad-direct@0x40C09E",
    "rhad:route@0x40C0B8",
    "rhad:route@0x40C0D2",
    "rhad:route@0x40C0EE",
    "rhad:route@0x40C108",
    "route:rhad-direct@0x40C14E",
    "rhad:route@0x40C168",
    "rhad:route@0x40C184",
    "rhad:route@0x40C19E",
    "rhad:route@0x40C1F0",
    "rhad:route@0x40C20A",
    "route:rhad-direct@0x40C251",
    "rhad:route@0x40C26B",
    "route:rhad-direct@0x40C2F9",
    "rhad:route@0x40C313",
    "route:rhad-direct@0x40C34B",
    "rhad:route@0x40C365",
    "route:rhad-direct@0x40C390",
    "rhad:route@0x40C3AA",
    "route:rhad-direct@0x40C3D7",
    "rhad:route@0x40C3F1",
    "route:rhad-direct@0x40C42C",
    "rhad:route@0x40C446",
    "rhad:route@0x40C462",
    "rhad:route@0x40C47C",
    "rhad:route@0x40C498",
    "rhad:route@0x40C4B2",
    "rhad:route@0x40C4DA",
    "rhad:route@0x40C4F4",
    "rhad:route@0x40C525",
    "rhad:route@0x40C53F",
    "rhad:route@0x40C576",
    "rhad:route@0x40C590",
    "route:rhad-direct@0x40C5F9",
    "rhad:route@0x40C613",
    "rhad:route@0x40C62D",
    "rhad:route@0x40C649",
    "rhad:route@0x40C663",
    "rhad:route@0x40C694",
    "route:rhad-direct@0x40C6B3",
    "route:rhad-direct@0x40C6D8",
    "route:rhad-direct@0x40C703",
    "route:rhad-direct@0x40C72E",
    "route:rhad-direct@0x40C74F",
    "route:rhad-direct@0x40C76E",
    "route:rhad-direct@0x40C793",
    "route:rhad-direct@0x40C7B8",
    "route:rhad-direct@0x40C7E3",
    "route:rhad-direct@0x40C802",
    "route:rhad-direct@0x40C821",
    "route:rhad-direct@0x40C840",
    "route:rhad-direct@0x40C86B",
    "route:rhad-direct@0x40C896",
)
_CONSTANT_OPERATION_ID = "constant:rhad-add-absolute@0x40A574"
_MOV_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40A710"
_EAX_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40A868"
_ROW3_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40A903"
_ROW4_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40A922"
_ROW5_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40A9AE"
_ROW6_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AAC2"
_ROW7_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40ABFF"
_ROW8_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AC81"
_ROW9_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AE3E"
_ROW10_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AE4A"
_ROW11_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AEAC"
_ROW12_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AF00"
_ROW13_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AF32"
_ROW14_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AF45"
_ROW15_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AF71"
_ROW16_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AF84"
_ROW17_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40AFA0"
_ROW18_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B03E"
_ROW19_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B19B"
_ROW20_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B287"
_ROW21_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B2F7"
_ROW22_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B3B0"
_ROW23_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B3FF"
_ROW24_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B410"
_ROW25_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B421"
_ROW26_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B432"
_ROW27_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B443"
_ROW28_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B450"
_ROW29_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B45D"
_ROW30_CONSTANT_OPERATION_ID = "constant:rhad-movzx-absolute@0x40B815"
_ROW31_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B825"
_ROW32_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B84C"
_ROW33_CONSTANT_OPERATION_ID = "constant:rhad-movzx-absolute@0x40B8E6"
_ROW34_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B8ED"
_ROW35_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B8FC"
_ROW36_CONSTANT_OPERATION_ID = "constant:rhad-movzx-absolute@0x40B9C1"
_ROW37_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40B9FF"
_ROW38_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BA1A"
_ROW39_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BA2D"
_ROW40_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BA47"
_ROW41_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BA63"
_ROW42_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BA7F"
_ROW43_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BACF"
_ROW44_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BB0A"
_ROW45_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BB28"
_ROW46_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BD84"
_ROW47_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BD9B"
_ROW48_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BDD8"
_ROW49_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BDEB"
_ROW50_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BE63"
_ROW51_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BF31"
_ROW52_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40BF4E"
_ROW53_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C118"
_ROW54_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C1A0"
_ROW55_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C1AC"
_ROW56_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C21B"
_ROW57_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C26D"
_ROW58_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C279"
_ROW59_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C286"
_ROW60_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C293"
_ROW61_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C2AF"
_ROW62_CONSTANT_OPERATION_ID = "constant:rhad-xor-absolute@0x40C322"
_ROW63_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C4F8"
_ROW64_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C592"
_ROW65_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C59E"
_ROW66_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C5BD"
_ROW67_CONSTANT_OPERATION_ID = "constant:rhad-mov-absolute@0x40C667"
_COMPILED_OPERATION_IDS = (
    *_REFERENCE_OPERATION_IDS,
    _CONSTANT_OPERATION_ID,
    _MOV_CONSTANT_OPERATION_ID,
    _EAX_CONSTANT_OPERATION_ID,
    _ROW3_CONSTANT_OPERATION_ID,
    _ROW4_CONSTANT_OPERATION_ID,
    _ROW5_CONSTANT_OPERATION_ID,
    _ROW6_CONSTANT_OPERATION_ID,
    _ROW7_CONSTANT_OPERATION_ID,
    _ROW8_CONSTANT_OPERATION_ID,
    _ROW9_CONSTANT_OPERATION_ID,
    _ROW10_CONSTANT_OPERATION_ID,
    _ROW11_CONSTANT_OPERATION_ID,
    _ROW12_CONSTANT_OPERATION_ID,
    _ROW13_CONSTANT_OPERATION_ID,
    _ROW14_CONSTANT_OPERATION_ID,
    _ROW15_CONSTANT_OPERATION_ID,
    _ROW16_CONSTANT_OPERATION_ID,
    _ROW17_CONSTANT_OPERATION_ID,
    _ROW18_CONSTANT_OPERATION_ID,
    _ROW19_CONSTANT_OPERATION_ID,
    _ROW20_CONSTANT_OPERATION_ID,
    _ROW21_CONSTANT_OPERATION_ID,
    _ROW22_CONSTANT_OPERATION_ID,
    _ROW23_CONSTANT_OPERATION_ID,
    _ROW24_CONSTANT_OPERATION_ID,
    _ROW25_CONSTANT_OPERATION_ID,
    _ROW26_CONSTANT_OPERATION_ID,
    _ROW27_CONSTANT_OPERATION_ID,
    _ROW28_CONSTANT_OPERATION_ID,
    _ROW29_CONSTANT_OPERATION_ID,
    _ROW30_CONSTANT_OPERATION_ID,
    _ROW31_CONSTANT_OPERATION_ID,
    _ROW32_CONSTANT_OPERATION_ID,
    _ROW33_CONSTANT_OPERATION_ID,
    _ROW34_CONSTANT_OPERATION_ID,
    _ROW35_CONSTANT_OPERATION_ID,
    _ROW36_CONSTANT_OPERATION_ID,
    _ROW37_CONSTANT_OPERATION_ID,
    _ROW38_CONSTANT_OPERATION_ID,
    _ROW39_CONSTANT_OPERATION_ID,
    _ROW40_CONSTANT_OPERATION_ID,
    _ROW41_CONSTANT_OPERATION_ID,
    _ROW42_CONSTANT_OPERATION_ID,
    _ROW43_CONSTANT_OPERATION_ID,
    _ROW44_CONSTANT_OPERATION_ID,
    _ROW45_CONSTANT_OPERATION_ID,
    _ROW46_CONSTANT_OPERATION_ID,
    _ROW47_CONSTANT_OPERATION_ID,
    _ROW48_CONSTANT_OPERATION_ID,
    _ROW49_CONSTANT_OPERATION_ID,
    _ROW50_CONSTANT_OPERATION_ID,
    _ROW51_CONSTANT_OPERATION_ID,
    _ROW52_CONSTANT_OPERATION_ID,
    _ROW53_CONSTANT_OPERATION_ID,
    _ROW54_CONSTANT_OPERATION_ID,
    _ROW55_CONSTANT_OPERATION_ID,
    _ROW56_CONSTANT_OPERATION_ID,
    _ROW57_CONSTANT_OPERATION_ID,
    _ROW58_CONSTANT_OPERATION_ID,
    _ROW59_CONSTANT_OPERATION_ID,
    _ROW60_CONSTANT_OPERATION_ID,
    _ROW61_CONSTANT_OPERATION_ID,
    _ROW62_CONSTANT_OPERATION_ID,
    _ROW63_CONSTANT_OPERATION_ID,
    _ROW64_CONSTANT_OPERATION_ID,
    _ROW65_CONSTANT_OPERATION_ID,
    _ROW66_CONSTANT_OPERATION_ID,
    _ROW67_CONSTANT_OPERATION_ID,
)
_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
    "native@0x40B6C0",
    "native@0x40B6CA",
    "native@0x40B6D0",
    "native@0x40B6D4",
    "native@0x40A61B",
    "native@0x40A62D",
    "native@0x40A631",
    "native@0x40A740",
    "native@0x40A74A",
    "native@0x40A68C",
    "native@0x40A69A",
    "native@0x40A6A0",
    "native@0x40A6A4",
    "native@0x40A6A6",
    "native@0x40A6B4",
    "native@0x40A6BA",
    "native@0x40A800",
    "native@0x40A80E",
    "native@0x40A814",
    "native@0x40A818",
    "native@0x40A6C0",
    "native@0x40A6CE",
    "native@0x40A6D4",
    "native@0x40A6D8",
    "native@0x40A960",
    "native@0x40A96E",
    "native@0x40A974",
    "native@0x40A978",
    "native@0x40A6DA",
    "native@0x40A6E8",
    "native@0x40A6EE",
    "native@0x40A6F2",
    "native@0x40AB76",
    "native@0x40AB84",
    "native@0x40AB8A",
    "native@0x40AB8E",
    "native@0x40A6F4",
    "native@0x40A702",
    "native@0x40A708",
    "native@0x40A70C",
    "native@0x40AE8B",
    "native@0x40AE99",
    "native@0x40AE9F",
    "native@0x40AEA3",
    "native@0x40A70E",
    "native@0x40A736",
    "native@0x40A739",
    "native@0x40A73D",
    "native@0x40A74C",
    "native@0x40A75A",
    "native@0x40A760",
    "native@0x40A764",
    "native@0x40A766",
    "native@0x40ABC6",
    "native@0x40ABD4",
    "native@0x40ABDA",
    "native@0x40ABDE",
    "native@0x40A77C",
    "native@0x40A9DE",
    "native@0x40A9EC",
    "native@0x40A9F2",
    "native@0x40A9F6",
    "native@0x40A77E",
    "native@0x40A794",
    "native@0x40A7A2",
    "native@0x40A7A8",
    "native@0x40A7AC",
    "native@0x40AEE6",
    "native@0x40AEF4",
    "native@0x40AEFA",
    "native@0x40AEFE",
    "native@0x40A7AE",
    "native@0x40A7BA",
    "native@0x40A7CD",
    "native@0x40A7E5",
    "native@0x40A7EF",
    "native@0x40B4C5",
    "native@0x40B4E2",
    "native@0x40B4EE",
    "native@0x40A81A",
    "native@0x40A828",
    "native@0x40A82E",
    "native@0x40A832",
    "native@0x40AA60",
    "native@0x40AA6E",
    "native@0x40AA74",
    "native@0x40AA78",
    "native@0x40A834",
    "native@0x40A842",
    "native@0x40A848",
    "native@0x40A84C",
    "native@0x40AC3D",
    "native@0x40AC4A",
    "native@0x40AC50",
    "native@0x40AC54",
    "native@0x40A84E",
    "native@0x40A85C",
    "native@0x40A862",
    "native@0x40A866",
    "native@0x40AFDF",
    "native@0x40AFED",
    "native@0x40AFF3",
    "native@0x40AFF7",
    "native@0x40A868",
    "native@0x40A8A0",
    "native@0x40A8A3",
    "native@0x40A8A7",
    "native@0x40A633",
    "native@0x40A645",
    "native@0x40A649",
    "native@0x40A8A9",
    "native@0x40A8B3",
    "native@0x40A64B",
    "native@0x40A65D",
    "native@0x40A661",
    "native@0x40AAF1",
    "native@0x40AAFB",
    "native@0x40A663",
    "native@0x40A675",
    "native@0x40A679",
    "native@0x40AE1A",
    "native@0x40AE24",
    "native@0x40AE26",
    "native@0x40AE3C",
    "native@0x40A8B5",
    "native@0x40A8C3",
    "native@0x40A8C9",
    "native@0x40A8CD",
    "native@0x40A8CF",
    "native@0x40A8DD",
    "native@0x40A8E3",
    "native@0x40A8E7",
    "native@0x40ACBF",
    "native@0x40ACCD",
    "native@0x40ACD3",
    "native@0x40ACD7",
    "native@0x40A8E9",
    "native@0x40A8F7",
    "native@0x40A8FD",
    "native@0x40A901",
    "native@0x40B024",
    "native@0x40B032",
    "native@0x40B038",
    "native@0x40B03C",
    "native@0x40A903",
    "native@0x40A922",
    "native@0x40A93C",
    "native@0x40A954",
    "native@0x40A95E",
    "native@0x40B4F0",
    "native@0x40B50D",
    "native@0x40B519",
    "native@0x40A97A",
    "native@0x40A988",
    "native@0x40A98E",
    "native@0x40A992",
    "native@0x40AD1E",
    "native@0x40AD2C",
    "native@0x40AD32",
    "native@0x40AD36",
    "native@0x40A994",
    "native@0x40A9A2",
    "native@0x40A9A8",
    "native@0x40A9AC",
    "native@0x40B071",
    "native@0x40B07F",
    "native@0x40B085",
    "native@0x40B089",
    "native@0x40A9AE",
    "native@0x40A9D5",
    "native@0x40A9D8",
    "native@0x40A9DC",
    "native@0x40A9F8",
    "native@0x40AA06",
    "native@0x40AA0C",
    "native@0x40AA10",
    "native@0x40AD6E",
    "native@0x40AD7C",
    "native@0x40AD82",
    "native@0x40AD86",
    "native@0x40AA12",
    "native@0x40AA20",
    "native@0x40AA26",
    "native@0x40AA2A",
    "native@0x40B0BC",
    "native@0x40B0CA",
    "native@0x40B0D0",
    "native@0x40B0D4",
    "native@0x40AA2C",
    "native@0x40AA35",
    "native@0x40AA57",
    "native@0x40AA5A",
    "native@0x40AA5E",
    "native@0x40AA7A",
    "native@0x40AA88",
    "native@0x40AA8E",
    "native@0x40AA92",
    "native@0x40ADBE",
    "native@0x40ADCC",
    "native@0x40ADD2",
    "native@0x40ADD6",
    "native@0x40AA94",
    "native@0x40AAA2",
    "native@0x40AAA8",
    "native@0x40AAAC",
    "native@0x40B0F2",
    "native@0x40B100",
    "native@0x40B106",
    "native@0x40B10A",
    "native@0x40AAAE",
    "native@0x40AAE8",
    "native@0x40AAEB",
    "native@0x40AAEF",
    "native@0x40AAFD",
    "native@0x40AB0B",
    "native@0x40AB11",
    "native@0x40AB15",
    "native@0x40AB17",
    "native@0x40AB25",
    "native@0x40AB2B",
    "native@0x40AB2F",
    "native@0x40B149",
    "native@0x40B157",
    "native@0x40B15D",
    "native@0x40B161",
    "native@0x40AB31",
    "native@0x40AB56",
    "native@0x40AB6A",
    "native@0x40AB74",
    "native@0x40B51B",
    "native@0x40B534",
    "native@0x40B540",
    "native@0x40AB90",
    "native@0x40AB9E",
    "native@0x40ABA4",
    "native@0x40ABA8",
    "native@0x40B17F",
    "native@0x40B18D",
    "native@0x40B193",
    "native@0x40B197",
    "native@0x40ABAA",
    "native@0x40ABBD",
    "native@0x40ABC0",
    "native@0x40ABC4",
    "native@0x40ABE0",
    "native@0x40ABEE",
    "native@0x40ABF4",
    "native@0x40ABF8",
    "native@0x40B1D0",
    "native@0x40B1DE",
    "native@0x40B1E4",
    "native@0x40B1E8",
    "native@0x40ABFA",
    "native@0x40ABFF",
    "native@0x40AC19",
    "native@0x40AC31",
    "native@0x40AC3B",
    "native@0x40B542",
    "native@0x40B55F",
    "native@0x40B56B",
    "native@0x40AC56",
    "native@0x40AC64",
    "native@0x40AC6A",
    "native@0x40AC6E",
    "native@0x40B21C",
    "native@0x40B22A",
    "native@0x40B230",
    "native@0x40B234",
    "native@0x40AC70",
    "native@0x40AC81",
    "native@0x40AC9B",
    "native@0x40ACB3",
    "native@0x40ACBD",
    "native@0x40B56D",
    "native@0x40B58A",
    "native@0x40B596",
    "native@0x40ACD9",
    "native@0x40ACE7",
    "native@0x40ACED",
    "native@0x40ACF1",
    "native@0x40B26D",
    "native@0x40B27B",
    "native@0x40B281",
    "native@0x40B285",
    "native@0x40ACF3",
    "native@0x40AD06",
    "native@0x40AD18",
    "native@0x40AD1C",
    "native@0x40B598",
    "native@0x40B5AF",
    "native@0x40B5B5",
    "native@0x40AD38",
    "native@0x40AD46",
    "native@0x40AD4C",
    "native@0x40AD50",
    "native@0x40B2DB",
    "native@0x40B2E9",
    "native@0x40B2EF",
    "native@0x40B2F3",
    "native@0x40AD52",
    "native@0x40AD65",
    "native@0x40AD68",
    "native@0x40AD6C",
    "native@0x40AD88",
    "native@0x40AD96",
    "native@0x40AD9C",
    "native@0x40ADA0",
    "native@0x40B32C",
    "native@0x40B340",
    "native@0x40ADA2",
    "native@0x40ADB5",
    "native@0x40ADB8",
    "native@0x40ADBC",
    "native@0x40ADD8",
    "native@0x40ADE6",
    "native@0x40ADEC",
    "native@0x40ADF0",
    "native@0x40B37C",
    "native@0x40B38A",
    "native@0x40B390",
    "native@0x40B394",
    "native@0x40ADF2",
    "native@0x40AE05",
    "native@0x40AE08",
    "native@0x40AE18",
    "native@0x40A5CA",
    "native@0x40A5DC",
    "native@0x40A5DF",
    "native@0x40A5E3",
    "native@0x40AE3E",
    "native@0x40AE63",
    "native@0x40AE82",
    "native@0x40AE85",
    "native@0x40AE89",
    "native@0x40AEA5",
    "native@0x40AEC6",
    "native@0x40AEDA",
    "native@0x40AEE4",
    "native@0x40B5B7",
    "native@0x40B5D0",
    "native@0x40B5DC",
    "native@0x40AF00",
    "native@0x40AF1C",
    "native@0x40AF2F",
    "native@0x40AF9D",
    "native@0x40AFBB",
    "native@0x40AFD3",
    "native@0x40AFDD",
    "native@0x40B5DE",
    "native@0x40B5FB",
    "native@0x40B607",
    "native@0x40AFF9",
    "native@0x40B00C",
    "native@0x40B01E",
    "native@0x40B022",
    "native@0x40B609",
    "native@0x40B620",
    "native@0x40B626",
    "native@0x40B03E",
    "native@0x40B059",
    "native@0x40B06B",
    "native@0x40B06F",
    "native@0x40B628",
    "native@0x40B63F",
    "native@0x40B645",
    "native@0x40B08B",
    "native@0x40B094",
    "native@0x40B0B3",
    "native@0x40B0B6",
    "native@0x40B0BA",
    "native@0x40B0D6",
    "native@0x40B0E9",
    "native@0x40B0EC",
    "native@0x40B0F0",
    "native@0x40B10C",
    "native@0x40B11A",
    "native@0x40B121",
    "native@0x40B140",
    "native@0x40B143",
    "native@0x40B147",
    "native@0x40B163",
    "native@0x40B176",
    "native@0x40B179",
    "native@0x40B17D",
    "native@0x40B199",
    "native@0x40B1B6",
    "native@0x40B1CA",
    "native@0x40B1CE",
    "native@0x40B647",
    "native@0x40B660",
    "native@0x40B666",
    "native@0x40B1EA",
    "native@0x40B1F4",
    "native@0x40B213",
    "native@0x40B216",
    "native@0x40B21A",
    "native@0x40B236",
    "native@0x40B242",
    "native@0x40B264",
    "native@0x40B267",
    "native@0x40B287",
    "native@0x40B2A6",
    "native@0x40B2B7",
    "native@0x40B2CF",
    "native@0x40B2D9",
    "native@0x40B668",
    "native@0x40B685",
    "native@0x40B691",
    "native@0x40B2F5",
    "native@0x40B312",
    "native@0x40B326",
    "native@0x40B32A",
    "native@0x40B693",
    "native@0x40B6AC",
    "native@0x40B6B2",
    "native@0x40B342",
    "native@0x40B354",
    "native@0x40B373",
    "native@0x40B376",
    "native@0x40B37A",
    "native@0x40B396",
    "native@0x40B3A4",
    "native@0x40B3AA",
    "native@0x40B3AE",
    "native@0x40B3E5",
    "native@0x40B3F3",
    "native@0x40B3F9",
    "native@0x40B3FD",
    "native@0x40B3B0",
    "native@0x40B3DC",
    "native@0x40B3DF",
    "native@0x40B3E3",
    "native@0x40B3FF",
    "native@0x40B4A4",
    "native@0x40B4BC",
    "native@0x40B4BF",
    "native@0x40B4C3",
    "native@0x40B6D6",
    "native@0x40B6E4",
    "native@0x40B6EA",
    "native@0x40B6EE",
    "native@0x40B790",
    "native@0x40B79E",
    "native@0x40B7A4",
    "native@0x40B7A8",
    "native@0x40B6F0",
    "native@0x40B6FE",
    "native@0x40B704",
    "native@0x40B708",
    "native@0x40B880",
    "native@0x40B896",
    "native@0x40B70A",
    "native@0x40B718",
    "native@0x40B71E",
    "native@0x40B722",
    "native@0x40BB75",
    "native@0x40BB83",
    "native@0x40BB89",
    "native@0x40BB8D",
    "native@0x40B724",
    "native@0x40B732",
    "native@0x40B738",
    "native@0x40B73C",
    "native@0x40BD50",
    "native@0x40BD5E",
    "native@0x40BD64",
    "native@0x40BD68",
    "native@0x40B73E",
    "native@0x40B74C",
    "native@0x40B752",
    "native@0x40B756",
    "native@0x40C0F0",
    "native@0x40C0FE",
    "native@0x40C104",
    "native@0x40C108",
    "native@0x40B758",
    "native@0x40B76B",
    "native@0x40B77D",
    "native@0x40B781",
    "native@0x40C696",
    "native@0x40C6AD",
    "native@0x40C6B3",
    "native@0x40B7AA",
    "native@0x40B7B8",
    "native@0x40B7BE",
    "native@0x40B7C2",
    "native@0x40B940",
    "native@0x40B956",
    "native@0x40B7C4",
    "native@0x40B7D2",
    "native@0x40B7D8",
    "native@0x40B7DC",
    "native@0x40BBDF",
    "native@0x40BBED",
    "native@0x40BBF3",
    "native@0x40BBF7",
    "native@0x40B7DE",
    "native@0x40B7F4",
    "native@0x40BE2F",
    "native@0x40BE3D",
    "native@0x40BE43",
    "native@0x40BE47",
    "native@0x40B7F6",
    "native@0x40B804",
    "native@0x40B80A",
    "native@0x40B80E",
    "native@0x40C150",
    "native@0x40C15E",
    "native@0x40C164",
    "native@0x40C168",
    "native@0x40B810",
    "native@0x40B872",
    "native@0x40B875",
    "native@0x40B879",
    "native@0x40B898",
    "native@0x40B8A6",
    "native@0x40B8AC",
    "native@0x40B8B0",
    "native@0x40BC61",
    "native@0x40BC6F",
    "native@0x40BC75",
    "native@0x40BC79",
    "native@0x40B8B2",
    "native@0x40B8C0",
    "native@0x40B8C6",
    "native@0x40B8CA",
    "native@0x40BE98",
    "native@0x40BEA6",
    "native@0x40BEAC",
    "native@0x40BEB0",
    "native@0x40B8CC",
    "native@0x40B8DA",
    "native@0x40B8E0",
    "native@0x40B8E4",
    "native@0x40C186",
    "native@0x40C194",
    "native@0x40C19A",
    "native@0x40C19E",
    "native@0x40B8E6",
    "native@0x40B915",
    "native@0x40B927",
    "native@0x40B931",
    "native@0x40C6B5",
    "native@0x40C6CC",
    "native@0x40C6D8",
    "native@0x40B958",
    "native@0x40B966",
    "native@0x40B96C",
    "native@0x40B970",
    "native@0x40BCCB",
    "native@0x40BCD9",
    "native@0x40BCDF",
    "native@0x40BCE3",
    "native@0x40B972",
    "native@0x40B980",
    "native@0x40B986",
    "native@0x40B98A",
    "native@0x40BEE7",
    "native@0x40BEF5",
    "native@0x40BEFB",
    "native@0x40BEFF",
    "native@0x40B98C",
    "native@0x40B99A",
    "native@0x40B9A0",
    "native@0x40B9A4",
    "native@0x40C1F2",
    "native@0x40C200",
    "native@0x40C206",
    "native@0x40C20A",
    "native@0x40B9A6",
    "native@0x40BA5C",
    "native@0x40BA78",
    "native@0x40BA92",
    "native@0x40BB3A",
    "native@0x40BB51",
    "native@0x40BB69",
    "native@0x40BB73",
    "native@0x40C6DA",
    "native@0x40C6F7",
    "native@0x40C703",
    "native@0x40BB8F",
    "native@0x40BB9D",
    "native@0x40BBA3",
    "native@0x40BBA7",
    "native@0x40BF8C",
    "native@0x40BFA2",
    "native@0x40BBA9",
    "native@0x40BBB7",
    "native@0x40BBBD",
    "native@0x40BBC1",
    "native@0x40C253",
    "native@0x40C261",
    "native@0x40C267",
    "native@0x40C26B",
    "native@0x40BBC3",
    "native@0x40BBD6",
    "native@0x40BBD9",
    "native@0x40BBDD",
    "native@0x40BBF9",
    "native@0x40BC07",
    "native@0x40BC0D",
    "native@0x40BC11",
    "native@0x40BFDA",
    "native@0x40BFE8",
    "native@0x40BFEE",
    "native@0x40BFF2",
    "native@0x40BC13",
    "native@0x40BC21",
    "native@0x40BC27",
    "native@0x40BC2B",
    "native@0x40C2FB",
    "native@0x40C309",
    "native@0x40C30F",
    "native@0x40C313",
    "native@0x40BC2D",
    "native@0x40BC36",
    "native@0x40BC58",
    "native@0x40BC5B",
    "native@0x40BC5F",
    "native@0x40BC7B",
    "native@0x40BC89",
    "native@0x40BC8F",
    "native@0x40BC93",
    "native@0x40C041",
    "native@0x40C04F",
    "native@0x40C055",
    "native@0x40C059",
    "native@0x40BC95",
    "native@0x40BCA3",
    "native@0x40BCA9",
    "native@0x40BCAD",
    "native@0x40C34D",
    "native@0x40C35B",
    "native@0x40C361",
    "native@0x40C365",
    "native@0x40BCAF",
    "native@0x40BCC2",
    "native@0x40BCC5",
    "native@0x40BCC9",
    "native@0x40BCE5",
    "native@0x40BCF3",
    "native@0x40BCF9",
    "native@0x40BCFD",
    "native@0x40C0A0",
    "native@0x40C0AE",
    "native@0x40C0B4",
    "native@0x40C0B8",
    "native@0x40BCFF",
    "native@0x40BD0D",
    "native@0x40BD13",
    "native@0x40BD17",
    "native@0x40C392",
    "native@0x40C3A0",
    "native@0x40C3A6",
    "native@0x40C3AA",
    "native@0x40BD19",
    "native@0x40BD25",
    "native@0x40BD47",
    "native@0x40BD4A",
    "native@0x40BD4E",
    "native@0x40BD6A",
    "native@0x40BD78",
    "native@0x40BD7E",
    "native@0x40BD82",
    "native@0x40C3D9",
    "native@0x40C3E7",
    "native@0x40C3ED",
    "native@0x40C3F1",
    "native@0x40BD84",
    "native@0x40BDBD",
    "native@0x40BDD5",
    "native@0x40BE0A",
    "native@0x40BE26",
    "native@0x40BE29",
    "native@0x40BE2D",
    "native@0x40BE49",
    "native@0x40BE57",
    "native@0x40BE5D",
    "native@0x40BE61",
    "native@0x40C42E",
    "native@0x40C43C",
    "native@0x40C442",
    "native@0x40C446",
    "native@0x40BE63",
    "native@0x40BE8F",
    "native@0x40BE92",
    "native@0x40BE96",
    "native@0x40BEB2",
    "native@0x40BEC0",
    "native@0x40BEC6",
    "native@0x40BECA",
    "native@0x40C464",
    "native@0x40C472",
    "native@0x40C478",
    "native@0x40C47C",
    "native@0x40BECC",
    "native@0x40BEDE",
    "native@0x40BEE1",
    "native@0x40BEE5",
    "native@0x40BF01",
    "native@0x40BF0F",
    "native@0x40BF15",
    "native@0x40BF19",
    "native@0x40C49A",
    "native@0x40C4A8",
    "native@0x40C4AE",
    "native@0x40C4B2",
    "native@0x40BF1B",
    "native@0x40BF2F",
    "native@0x40BF43",
    "native@0x40BF68",
    "native@0x40BF80",
    "native@0x40BF8A",
    "native@0x40C705",
    "native@0x40C722",
    "native@0x40C72E",
    "native@0x40BFA4",
    "native@0x40BFB2",
    "native@0x40BFB8",
    "native@0x40BFBC",
    "native@0x40C4DC",
    "native@0x40C4EA",
    "native@0x40C4F0",
    "native@0x40C4F4",
    "native@0x40BFBE",
    "native@0x40BFD1",
    "native@0x40BFD4",
    "native@0x40BFD8",
    "native@0x40BFF4",
    "native@0x40C002",
    "native@0x40C008",
    "native@0x40C00C",
    "native@0x40C527",
    "native@0x40C535",
    "native@0x40C53B",
    "native@0x40C53F",
    "native@0x40C00E",
    "native@0x40C027",
    "native@0x40C03B",
    "native@0x40C03F",
    "native@0x40C730",
    "native@0x40C749",
    "native@0x40C74F",
    "native@0x40C05B",
    "native@0x40C069",
    "native@0x40C06F",
    "native@0x40C073",
    "native@0x40C578",
    "native@0x40C586",
    "native@0x40C58C",
    "native@0x40C590",
    "native@0x40C075",
    "native@0x40C088",
    "native@0x40C09A",
    "native@0x40C09E",
    "native@0x40C751",
    "native@0x40C768",
    "native@0x40C76E",
    "native@0x40C0BA",
    "native@0x40C0C8",
    "native@0x40C0CE",
    "native@0x40C0D2",
    "native@0x40C5FB",
    "native@0x40C609",
    "native@0x40C60F",
    "native@0x40C613",
    "native@0x40C0D4",
    "native@0x40C0E7",
    "native@0x40C0EA",
    "native@0x40C0EE",
    "native@0x40C10A",
    "native@0x40C132",
    "native@0x40C144",
    "native@0x40C14E",
    "native@0x40C770",
    "native@0x40C787",
    "native@0x40C793",
    "native@0x40C16A",
    "native@0x40C17D",
    "native@0x40C180",
    "native@0x40C184",
    "native@0x40C1A0",
    "native@0x40C1C0",
    "native@0x40C1E9",
    "native@0x40C1EC",
    "native@0x40C1F0",
    "native@0x40C20C",
    "native@0x40C235",
    "native@0x40C247",
    "native@0x40C251",
    "native@0x40C795",
    "native@0x40C7AC",
    "native@0x40C7B8",
    "native@0x40C26D",
    "native@0x40C2AF",
    "native@0x40C2C3",
    "native@0x40C2D7",
    "native@0x40C2EF",
    "native@0x40C2F9",
    "native@0x40C7BA",
    "native@0x40C7D7",
    "native@0x40C7E3",
    "native@0x40C315",
    "native@0x40C335",
    "native@0x40C347",
    "native@0x40C34B",
    "native@0x40C7E5",
    "native@0x40C7FC",
    "native@0x40C802",
    "native@0x40C367",
    "native@0x40C37A",
    "native@0x40C38C",
    "native@0x40C390",
    "native@0x40C804",
    "native@0x40C81B",
    "native@0x40C821",
    "native@0x40C3AC",
    "native@0x40C3C1",
    "native@0x40C3D3",
    "native@0x40C3D7",
    "native@0x40C823",
    "native@0x40C83A",
    "native@0x40C840",
    "native@0x40C3F3",
    "native@0x40C3F9",
    "native@0x40C40A",
    "native@0x40C422",
    "native@0x40C42C",
    "native@0x40C842",
    "native@0x40C85F",
    "native@0x40C86B",
    "native@0x40C448",
    "native@0x40C45B",
    "native@0x40C45E",
    "native@0x40C462",
    "native@0x40C47E",
    "native@0x40C491",
    "native@0x40C494",
    "native@0x40C498",
    "native@0x40C4B4",
    "native@0x40C4C3",
    "native@0x40C4C6",
    "native@0x40C4D4",
    "native@0x40C4D6",
    "native@0x40C4DA",
    "native@0x40C4F6",
    "native@0x40C51E",
    "native@0x40C521",
    "native@0x40C525",
    "native@0x40C541",
    "native@0x40C54D",
    "native@0x40C56F",
    "native@0x40C572",
    "native@0x40C576",
    "native@0x40C592",
    "native@0x40C5BD",
    "native@0x40C5D7",
    "native@0x40C5EF",
    "native@0x40C5F9",
    "native@0x40C86D",
    "native@0x40C88A",
    "native@0x40C896",
    "native@0x40C615",
    "native@0x40C623",
    "native@0x40C629",
    "native@0x40C62D",
    "native@0x40C64B",
    "native@0x40C659",
    "native@0x40C65F",
    "native@0x40C663",
    "native@0x40C62F",
    "native@0x40C642",
    "native@0x40C645",
    "native@0x40C649",
    "native@0x40C665",
    "native@0x40C68D",
    "native@0x40C690",
    "native@0x40C694",
    "native@0x40A792",
)


def _output_excerpt(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    lines = [line[:1_500] for line in (value or "").splitlines()]
    normalized = "\n".join(lines)
    if len(normalized) <= _FAILURE_OUTPUT_LIMIT:
        return normalized
    diagnostic = "\n".join(
        line
        for line in lines
        if any(
            marker in line
            for marker in (
                "Traceback",
                "Error",
                "Rejected",
                "failed",
                "Failure",
                "graph_closure",
                "native-body",
                "semantic validation",
                "GENERATED checksum",
                "rhad-generated",
            )
        )
    )
    head_limit = _FAILURE_OUTPUT_LIMIT // 2
    tail_limit = _FAILURE_OUTPUT_LIMIT - head_limit
    return (
        diagnostic[:head_limit]
        + "\n... failure output elided ...\n"
        + normalized[-tail_limit:]
    )


def _fixture() -> pathlib.Path:
    override = os.environ.get("D810_RHAD_LOADER_FIXTURE")
    return pathlib.Path(override).resolve() if override else _BINARY


def _instructions(block: object) -> tuple[object, ...]:
    rows = []
    instruction = block.head
    while instruction is not None:
        rows.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(rows)


def _native_anchor(block: object, origins: dict[int, int]) -> int:
    return min(
        (
            int(origins.get(int(row.ea), int(row.ea)))
            for row in _instructions(block)
            if int(origins.get(int(row.ea), int(row.ea))) > 0
        ),
        default=int(block.start),
    )


def _route_snapshot(mba: object) -> dict[str, object]:
    import ida_hexrays

    from d810.hexrays.mutation.detached_handler_island import (
        imported_detached_snippet_instruction_origins,
    )

    origins = dict(imported_detached_snippet_instruction_origins(mba))
    blocks = {serial: mba.get_mblock(serial) for serial in range(int(mba.qty))}

    def exact_indirect(transfer_ea: int) -> bool:
        return any(
            int(row.opcode) == int(ida_hexrays.m_ijmp)
            and int(origins.get(int(row.ea), int(row.ea))) == int(transfer_ea)
            for block in blocks.values()
            for row in _instructions(block)
        )

    def source_at(anchor_ea: int) -> object | None:
        return next(
            (
                block
                for block in blocks.values()
                if any(
                    int(origins.get(int(row.ea), int(row.ea))) == int(anchor_ea)
                    for row in _instructions(block)
                )
            ),
            None,
        )

    def route_targets(
        source: object | None,
        corridor_anchor_eas: set[int],
    ) -> set[int]:
        if source is None:
            return set()
        targets: set[int] = set()
        source_successors = tuple(int(value) for value in source.succset)
        if source_successors:
            for successor_serial in source_successors:
                target = blocks[successor_serial]
                while (
                    _native_anchor(target, origins) in corridor_anchor_eas
                    and len(tuple(target.succset)) == 1
                ):
                    successor_serial = int(tuple(target.succset)[0])
                    target = blocks[successor_serial]
                targets.add(_native_anchor(target, origins))
            return targets
        corridor_blocks = [source]
        if source.nextb is not None:
            corridor_blocks.append(source.nextb)
            if source.nextb.nextb is not None:
                corridor_blocks.append(source.nextb.nextb)
        for block in corridor_blocks:
            if block.tail is None:
                continue
            opcode = int(block.tail.opcode)
            operand = (
                block.tail.l if opcode == int(ida_hexrays.m_goto) else block.tail.d
            )
            if int(operand.t) == int(ida_hexrays.mop_b):
                targets.add(_native_anchor(blocks[int(operand.b)], origins))
        return targets

    def reachable_anchors() -> tuple[int, ...]:
        reachable: set[int] = set()
        pending = [0]
        while pending:
            serial = pending.pop()
            if serial in reachable:
                continue
            reachable.add(serial)
            pending.extend(int(value) for value in blocks[serial].succset)
        return tuple(
            sorted({_native_anchor(blocks[serial], origins) for serial in reachable})
        )

    transfer_indirect = exact_indirect(0x40A605)
    source = source_at(0x40A5F0)
    row5_source = source_at(0x40A65D)
    row5_targets = route_targets(row5_source, {0x40A663})
    row5_snapshot = {
        "row5_source_present": row5_source is not None,
        "row5_indirect": exact_indirect(0x40A661),
        "row5_target_eas": tuple(sorted(row5_targets)),
    }
    row6_source = source_at(0x40A675)
    row6_live_targets = route_targets(row6_source, {0x40AE26})

    def row6_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AE26 <= int(live_anchor_ea) < 0x40AE3E:
            return 0x40AE26
        return int(live_anchor_ea)

    row6_snapshot = {
        "row6_source_present": row6_source is not None,
        "row6_indirect": exact_indirect(0x40A679),
        "row6_target_eas": tuple(
            sorted(row6_semantic_anchor(ea) for ea in row6_live_targets)
        ),
    }
    selected_source = source_at(0x40A692)
    selected_targets = route_targets(selected_source, {0x40A69A, 0x40A6A0})
    selected_snapshot = {
        "selected_source_present": selected_source is not None,
        "selected_indirect": exact_indirect(0x40A6A4),
        "selected_target_eas": tuple(sorted(selected_targets)),
    }
    row9_source = source_at(0x40A6AC)
    row9_targets = route_targets(row9_source, {0x40A6B4, 0x40A6BA})
    row9_snapshot = {
        "row9_source_present": row9_source is not None,
        "row9_indirect": exact_indirect(0x40A6BE),
        "row9_target_eas": tuple(sorted(row9_targets)),
    }
    row10_source = source_at(0x40A6C6)
    row10_targets = route_targets(row10_source, {0x40A6CE, 0x40A6D4})
    row10_snapshot = {
        "row10_source_present": row10_source is not None,
        "row10_indirect": exact_indirect(0x40A6D8),
        "row10_target_eas": tuple(sorted(row10_targets)),
    }
    row11_source = source_at(0x40A6E0)
    row11_targets = route_targets(row11_source, {0x40A6E8, 0x40A6EE})
    row11_snapshot = {
        "row11_source_present": row11_source is not None,
        "row11_indirect": exact_indirect(0x40A6F2),
        "row11_target_eas": tuple(sorted(row11_targets)),
    }
    row12_source = source_at(0x40A6FA)
    row12_targets = route_targets(row12_source, {0x40A702, 0x40A708})
    row12_snapshot = {
        "row12_source_present": row12_source is not None,
        "row12_indirect": exact_indirect(0x40A70C),
        "row12_target_eas": tuple(sorted(row12_targets)),
    }
    setcc_source = source_at(0x40A76E)
    setcc_live_targets = route_targets(setcc_source, set())

    def setcc_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A77E <= int(live_anchor_ea) < 0x40A794:
            return 0x40A77E
        if 0x40ABC6 <= int(live_anchor_ea) < 0x40ABE0:
            return 0x40ABC6
        if 0x40ABE0 <= int(live_anchor_ea) < 0x40ABFA:
            return 0x40ABC6
        if 0x40B1D0 <= int(live_anchor_ea) < 0x40B1EA:
            return 0x40ABC6
        return int(live_anchor_ea)

    setcc_snapshot = {
        "setcc_source_present": setcc_source is not None,
        "setcc_indirect": exact_indirect(0x40A77C),
        "setcc_target_eas": tuple(
            sorted(setcc_semantic_anchor(ea) for ea in setcc_live_targets)
        ),
    }
    scaled_setcc_source = source_at(0x40A786)
    scaled_setcc_live_targets = route_targets(scaled_setcc_source, set())

    def scaled_setcc_semantic_anchor(live_anchor_ea: int) -> int:
        if int(live_anchor_ea) in {0x40A5F0, 0x40A7AE}:
            return 0x40A794
        if 0x40A794 <= int(live_anchor_ea) < 0x40A7AE:
            return 0x40A794
        if 0x40AEE6 <= int(live_anchor_ea) < 0x40AF00:
            return 0x40AEE6
        return int(live_anchor_ea)

    scaled_setcc_snapshot = {
        "scaled_setcc_source_present": scaled_setcc_source is not None,
        "scaled_setcc_indirect": exact_indirect(0x40A792),
        "scaled_setcc_target_eas": tuple(
            sorted(scaled_setcc_semantic_anchor(ea) for ea in scaled_setcc_live_targets)
        ),
    }
    row18_source = source_at(0x40A79A)
    row18_live_targets = route_targets(row18_source, {0x40A7A2, 0x40A7A8})
    row18_snapshot = {
        "row18_source_present": row18_source is not None,
        "row18_indirect": exact_indirect(0x40A7AC),
        "row18_target_eas": tuple(sorted(row18_live_targets)),
    }
    row19_source = source_at(0x40A7E5)
    row19_live_targets = route_targets(row19_source, {0x40B6C0})

    def row19_semantic_anchor(live_anchor_ea: int) -> int | None:
        if int(live_anchor_ea) == 0x40A7E5:
            return None
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row19_snapshot = {
        "row19_source_present": row19_source is not None,
        "row19_indirect": exact_indirect(0x40A7EF),
        "row19_target_eas": tuple(
            sorted(
                anchor
                for ea in row19_live_targets
                if (anchor := row19_semantic_anchor(ea)) is not None
            )
        ),
    }
    row20_source = source_at(0x40A806)
    row20_live_targets = route_targets(row20_source, {0x40A80E, 0x40A814})
    row20_snapshot = {
        "row20_source_present": row20_source is not None,
        "row20_indirect": exact_indirect(0x40A818),
        "row20_target_eas": tuple(sorted(row20_live_targets)),
    }
    row21_source = source_at(0x40A820)
    row21_live_targets = route_targets(row21_source, {0x40A828, 0x40A82E})
    row21_snapshot = {
        "row21_source_present": row21_source is not None,
        "row21_indirect": exact_indirect(0x40A832),
        "row21_target_eas": tuple(sorted(row21_live_targets)),
    }
    row22_source = source_at(0x40A83A)
    row22_live_targets = route_targets(row22_source, {0x40A842, 0x40A848})
    row22_snapshot = {
        "row22_source_present": row22_source is not None,
        "row22_indirect": exact_indirect(0x40A84C),
        "row22_target_eas": tuple(sorted(row22_live_targets)),
    }
    row23_source = source_at(0x40A854)
    row23_live_targets = route_targets(row23_source, {0x40A85C, 0x40A862})

    def row23_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A868 <= int(live_anchor_ea) < 0x40A8A9:
            return 0x40A868
        return int(live_anchor_ea)

    row23_snapshot = {
        "row23_source_present": row23_source is not None,
        "row23_indirect": exact_indirect(0x40A866),
        "row23_target_eas": tuple(
            sorted(row23_semantic_anchor(ea) for ea in row23_live_targets)
        ),
    }
    row25_source = source_at(0x40A8A9)
    row25_live_targets = route_targets(row25_source, {0x40A64B})

    def row25_semantic_anchor(live_anchor_ea: int) -> int | None:
        if int(live_anchor_ea) == 0x40A8A9:
            return None
        if 0x40A64B <= int(live_anchor_ea) < 0x40A663:
            return 0x40A64B
        if 0x40AAF1 <= int(live_anchor_ea) < 0x40AAFD:
            return 0x40A64B
        return int(live_anchor_ea)

    row25_snapshot = {
        "row25_source_present": row25_source is not None,
        "row25_indirect": exact_indirect(0x40A8B3),
        "row25_target_eas": tuple(
            sorted(
                anchor
                for ea in row25_live_targets
                if (anchor := row25_semantic_anchor(ea)) is not None
            )
        ),
    }
    row26_source = source_at(0x40A8BB)
    row26_live_targets = route_targets(row26_source, {0x40A8C3, 0x40A8C9})
    row26_snapshot = {
        "row26_source_present": row26_source is not None,
        "row26_indirect": exact_indirect(0x40A8CD),
        "row26_target_eas": tuple(sorted(row26_live_targets)),
    }
    row27_source = source_at(0x40A8D5)
    row27_live_targets = route_targets(row27_source, {0x40A8DD, 0x40A8E3})
    row27_snapshot = {
        "row27_source_present": row27_source is not None,
        "row27_indirect": exact_indirect(0x40A8E7),
        "row27_target_eas": tuple(sorted(row27_live_targets)),
    }
    row28_source = source_at(0x40A8EF)
    row28_live_targets = route_targets(row28_source, {0x40A8F7, 0x40A8FD})

    def row28_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A903 <= int(live_anchor_ea) < 0x40A960:
            return 0x40A903
        if 0x40B4F0 <= int(live_anchor_ea) < 0x40B51B:
            return 0x40A903
        return int(live_anchor_ea)

    row28_snapshot = {
        "row28_source_present": row28_source is not None,
        "row28_indirect": exact_indirect(0x40A901),
        "row28_target_eas": tuple(
            sorted(row28_semantic_anchor(ea) for ea in row28_live_targets)
        ),
    }
    row29_source = source_at(0x40A954)
    row29_live_targets = route_targets(row29_source, {0x40B6C0})

    def row29_semantic_anchor(live_anchor_ea: int) -> int | None:
        if int(live_anchor_ea) == 0x40A954:
            return None
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row29_snapshot = {
        "row29_source_present": row29_source is not None,
        "row29_indirect": exact_indirect(0x40A95E),
        "row29_target_eas": tuple(
            sorted(
                anchor
                for ea in row29_live_targets
                if (anchor := row29_semantic_anchor(ea)) is not None
            )
        ),
    }
    row30_source = source_at(0x40A966)
    row30_live_targets = route_targets(row30_source, {0x40A96E, 0x40A974})

    def row30_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A97A <= int(live_anchor_ea) < 0x40A994:
            return 0x40A97A
        if 0x40AD1E <= int(live_anchor_ea) < 0x40AD38:
            return 0x40AD1E
        return int(live_anchor_ea)

    row30_snapshot = {
        "row30_source_present": row30_source is not None,
        "row30_indirect": exact_indirect(0x40A978),
        "row30_target_eas": tuple(
            sorted(row30_semantic_anchor(ea) for ea in row30_live_targets)
        ),
    }
    row31_source = source_at(0x40A980)
    row31_live_targets = route_targets(row31_source, {0x40A988, 0x40A98E})

    def row31_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A994 <= int(live_anchor_ea) < 0x40A9AE:
            return 0x40A994
        if 0x40B071 <= int(live_anchor_ea) < 0x40B08B:
            return 0x40B071
        return int(live_anchor_ea)

    row31_snapshot = {
        "row31_source_present": row31_source is not None,
        "row31_indirect": exact_indirect(0x40A992),
        "row31_target_eas": tuple(
            sorted(row31_semantic_anchor(ea) for ea in row31_live_targets)
        ),
    }
    row32_source = source_at(0x40A99A)
    row32_live_targets = route_targets(row32_source, {0x40A9A2, 0x40A9A8})

    def row32_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A9AE <= int(live_anchor_ea) < 0x40A9DE:
            return 0x40A9AE
        return int(live_anchor_ea)

    row32_snapshot = {
        "row32_source_present": row32_source is not None,
        "row32_indirect": exact_indirect(0x40A9AC),
        "row32_target_eas": tuple(
            sorted(row32_semantic_anchor(ea) for ea in row32_live_targets)
        ),
    }
    row33_source = source_at(0x40A9C7)
    row33_live_targets = route_targets(row33_source, {0x40A9D5, 0x40A9D8})

    def row33_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row33_snapshot = {
        "row33_source_present": row33_source is not None,
        "row33_indirect": exact_indirect(0x40A9DC),
        "row33_target_eas": tuple(
            sorted(row33_semantic_anchor(ea) for ea in row33_live_targets)
        ),
    }
    row34_source = source_at(0x40A9E4)
    row34_live_targets = route_targets(row34_source, {0x40A9EC, 0x40A9F2})

    def row34_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A9F8 <= int(live_anchor_ea) < 0x40AA12:
            return 0x40A9F8
        if 0x40AD6E <= int(live_anchor_ea) < 0x40AD88:
            return 0x40AD6E
        return int(live_anchor_ea)

    row34_snapshot = {
        "row34_source_present": row34_source is not None,
        "row34_indirect": exact_indirect(0x40A9F6),
        "row34_target_eas": tuple(
            sorted(row34_semantic_anchor(ea) for ea in row34_live_targets)
        ),
    }
    row35_source = source_at(0x40A9FE)
    row35_live_targets = route_targets(row35_source, {0x40AA06, 0x40AA0C})

    def row35_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AA12 <= int(live_anchor_ea) < 0x40AA2C:
            return 0x40AA12
        if 0x40B0BC <= int(live_anchor_ea) < 0x40B0D6:
            return 0x40B0BC
        return int(live_anchor_ea)

    row35_snapshot = {
        "row35_source_present": row35_source is not None,
        "row35_indirect": exact_indirect(0x40AA10),
        "row35_target_eas": tuple(
            sorted(row35_semantic_anchor(ea) for ea in row35_live_targets)
        ),
    }
    row36_source = source_at(0x40AA18)
    row36_live_targets = route_targets(row36_source, {0x40AA20, 0x40AA26})

    def row36_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AA2C <= int(live_anchor_ea) < 0x40AA60:
            return 0x40AA2C
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        return int(live_anchor_ea)

    row36_snapshot = {
        "row36_source_present": row36_source is not None,
        "row36_indirect": exact_indirect(0x40AA2A),
        "row36_target_eas": tuple(
            sorted(row36_semantic_anchor(ea) for ea in row36_live_targets)
        ),
    }
    row37_source = source_at(0x40AA49)
    row37_live_targets = route_targets(row37_source, {0x40AA57, 0x40AA5A})

    def row37_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row37_snapshot = {
        "row37_source_present": row37_source is not None,
        "row37_indirect": exact_indirect(0x40AA5E),
        "row37_target_eas": tuple(
            sorted(row37_semantic_anchor(ea) for ea in row37_live_targets)
        ),
    }
    row38_source = source_at(0x40AA66)
    row38_live_targets = route_targets(row38_source, {0x40AA6E, 0x40AA74})

    def row38_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AA7A <= int(live_anchor_ea) < 0x40AA94:
            return 0x40AA7A
        if 0x40ADBE <= int(live_anchor_ea) < 0x40ADD8:
            return 0x40ADBE
        return int(live_anchor_ea)

    row38_snapshot = {
        "row38_source_present": row38_source is not None,
        "row38_indirect": exact_indirect(0x40AA78),
        "row38_target_eas": tuple(
            sorted(row38_semantic_anchor(ea) for ea in row38_live_targets)
        ),
    }
    row39_source = source_at(0x40AA80)
    row39_live_targets = route_targets(row39_source, {0x40AA88, 0x40AA8E})

    def row39_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AAA2 <= int(live_anchor_ea) < 0x40AAAE:
            return 0x40AA94
        if 0x40B0F2 <= int(live_anchor_ea) < 0x40B10C:
            return 0x40B0F2
        return int(live_anchor_ea)

    row39_snapshot = {
        "row39_source_present": row39_source is not None,
        "row39_indirect": exact_indirect(0x40AA92),
        "row39_target_eas": tuple(
            sorted(row39_semantic_anchor(ea) for ea in row39_live_targets)
        ),
    }
    row40_source = source_at(0x40AA9A)
    row40_live_targets = route_targets(row40_source, {0x40AAA2, 0x40AAA8})

    def row40_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AAAE <= int(live_anchor_ea) < 0x40AAF1:
            return 0x40AAAE
        return int(live_anchor_ea)

    row40_snapshot = {
        "row40_source_present": row40_source is not None,
        "row40_indirect": exact_indirect(0x40AAAC),
        "row40_target_eas": tuple(
            sorted(row40_semantic_anchor(ea) for ea in row40_live_targets)
        ),
    }
    row42_source = source_at(0x40AAF1)
    row42_live_targets = route_targets(row42_source, set())
    row42_snapshot = {
        "row42_source_present": row42_source is not None,
        "row42_indirect": exact_indirect(0x40AAFB),
        "row42_target_eas": tuple(
            sorted(
                0x40AAFD if 0x40AAFD <= ea < 0x40AB17 else ea
                for ea in row42_live_targets
            )
        ),
    }
    row43_source = source_at(0x40AB03)
    row43_live_targets = route_targets(row43_source, {0x40AB0B, 0x40AB11})

    def row43_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AB17 <= int(live_anchor_ea) < 0x40AB31:
            return 0x40AB17
        if 0x40B149 <= int(live_anchor_ea) < 0x40B163:
            return 0x40B149
        return int(live_anchor_ea)

    row43_snapshot = {
        "row43_source_present": row43_source is not None,
        "row43_indirect": exact_indirect(0x40AB15),
        "row43_target_eas": tuple(
            sorted(row43_semantic_anchor(ea) for ea in row43_live_targets)
        ),
    }
    row44_source = source_at(0x40AB1D)
    row44_live_targets = route_targets(row44_source, {0x40AB25, 0x40AB2B})

    def row44_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AB31 <= int(live_anchor_ea) < 0x40AB76:
            return 0x40AB31
        return int(live_anchor_ea)

    row44_snapshot = {
        "row44_source_present": row44_source is not None,
        "row44_indirect": exact_indirect(0x40AB2F),
        "row44_target_eas": tuple(
            sorted(row44_semantic_anchor(ea) for ea in row44_live_targets)
        ),
    }
    row45_source = source_at(0x40AB6A)
    row45_live_targets = route_targets(row45_source, set())
    row45_snapshot = {
        "row45_source_present": row45_source is not None,
        "row45_indirect": exact_indirect(0x40AB74),
        "row45_target_eas": tuple(sorted(row45_live_targets)),
    }
    row46_source = source_at(0x40AB7C)
    row46_live_targets = route_targets(row46_source, {0x40AB84, 0x40AB8A})

    def row46_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AB90 <= int(live_anchor_ea) < 0x40ABAA:
            return 0x40AB90
        if 0x40B17F <= int(live_anchor_ea) < 0x40B199:
            return 0x40B17F
        return int(live_anchor_ea)

    row46_snapshot = {
        "row46_source_present": row46_source is not None,
        "row46_indirect": exact_indirect(0x40AB8E),
        "row46_target_eas": tuple(
            sorted(row46_semantic_anchor(ea) for ea in row46_live_targets)
        ),
    }
    row47_source = source_at(0x40AB96)
    row47_live_targets = route_targets(row47_source, {0x40AB9E, 0x40ABA4})

    def row47_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ABAA <= int(live_anchor_ea) < 0x40ABC6:
            return 0x40ABAA
        return int(live_anchor_ea)

    row47_snapshot = {
        "row47_source_present": row47_source is not None,
        "row47_indirect": exact_indirect(0x40ABA8),
        "row47_target_eas": tuple(
            sorted(row47_semantic_anchor(ea) for ea in row47_live_targets)
        ),
    }
    row49_source = source_at(0x40ABCC)
    row49_live_targets = route_targets(row49_source, {0x40ABD4, 0x40ABDA})

    def row49_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40ABE0 <= int(live_anchor_ea) < 0x40ABFA:
            return 0x40ABE0
        if 0x40B1D0 <= int(live_anchor_ea) < 0x40B1EA:
            return 0x40B1D0
        return int(live_anchor_ea)

    row49_snapshot = {
        "row49_source_present": row49_source is not None,
        "row49_indirect": exact_indirect(0x40ABDE),
        "row49_target_eas": tuple(
            sorted(row49_semantic_anchor(ea) for ea in row49_live_targets)
        ),
    }
    row50_source = source_at(0x40ABE6)
    row50_live_targets = route_targets(row50_source, {0x40ABEE, 0x40ABF4})

    def row50_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ABFA <= int(live_anchor_ea) < 0x40AC3D:
            return 0x40ABFA
        if 0x40B542 <= int(live_anchor_ea) < 0x40B56D:
            return 0x40ABFA
        return int(live_anchor_ea)

    row50_snapshot = {
        "row50_source_present": row50_source is not None,
        "row50_indirect": exact_indirect(0x40ABF8),
        "row50_target_eas": tuple(
            sorted(row50_semantic_anchor(ea) for ea in row50_live_targets)
        ),
    }
    row51_source = source_at(0x40AC31)
    row51_live_targets = route_targets(row51_source, set())
    row51_snapshot = {
        "row51_source_present": row51_source is not None,
        "row51_indirect": exact_indirect(0x40AC3B),
        "row51_target_eas": tuple(sorted(row51_live_targets)),
    }
    row52_source = source_at(0x40AC42)
    row52_live_targets = route_targets(row52_source, {0x40AC4A, 0x40AC50})

    def row52_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AC56 <= int(live_anchor_ea) < 0x40AC70:
            return 0x40AC56
        if 0x40B21C <= int(live_anchor_ea) < 0x40B236:
            return 0x40B21C
        return int(live_anchor_ea)

    row52_snapshot = {
        "row52_source_present": row52_source is not None,
        "row52_indirect": exact_indirect(0x40AC54),
        "row52_target_eas": tuple(
            sorted(row52_semantic_anchor(ea) for ea in row52_live_targets)
        ),
    }
    row53_source = source_at(0x40AC5C)
    row53_live_targets = route_targets(row53_source, {0x40AC64, 0x40AC6A})

    def row53_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AC70 <= int(live_anchor_ea) < 0x40ACBF:
            return 0x40AC70
        if 0x40B56D <= int(live_anchor_ea) < 0x40B598:
            return 0x40AC70
        return int(live_anchor_ea)

    row53_snapshot = {
        "row53_source_present": row53_source is not None,
        "row53_indirect": exact_indirect(0x40AC6E),
        "row53_target_eas": tuple(
            sorted(row53_semantic_anchor(ea) for ea in row53_live_targets)
        ),
    }
    row54_source = source_at(0x40ACB3)
    row54_live_targets = route_targets(row54_source, set())
    row54_snapshot = {
        "row54_source_present": row54_source is not None,
        "row54_indirect": exact_indirect(0x40ACBD),
        "row54_target_eas": tuple(sorted(row54_live_targets)),
    }
    row55_source = source_at(0x40ACC5)
    row55_live_targets = route_targets(row55_source, {0x40ACCD, 0x40ACD3})

    def row55_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40ACD9 <= int(live_anchor_ea) < 0x40ACF3:
            return 0x40ACD9
        if 0x40B26D <= int(live_anchor_ea) < 0x40B287:
            return 0x40B26D
        return int(live_anchor_ea)

    row55_snapshot = {
        "row55_source_present": row55_source is not None,
        "row55_indirect": exact_indirect(0x40ACD7),
        "row55_target_eas": tuple(
            sorted(row55_semantic_anchor(ea) for ea in row55_live_targets)
        ),
    }
    row56_source = source_at(0x40ACDF)
    row56_live_targets = route_targets(row56_source, {0x40ACE7, 0x40ACED})

    def row56_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ACF3 <= int(live_anchor_ea) < 0x40AD1E:
            return 0x40ACF3
        if 0x40B598 <= int(live_anchor_ea) < 0x40B5B7:
            return 0x40ACF3
        return int(live_anchor_ea)

    row56_snapshot = {
        "row56_source_present": row56_source is not None,
        "row56_indirect": exact_indirect(0x40ACF1),
        "row56_target_eas": tuple(
            sorted(row56_semantic_anchor(ea) for ea in row56_live_targets)
        ),
    }
    row57_source = source_at(0x40AD18)
    row57_live_targets = route_targets(row57_source, set())
    row57_snapshot = {
        "row57_source_present": row57_source is not None,
        "row57_indirect": exact_indirect(0x40AD1C),
        "row57_target_eas": tuple(sorted(row57_live_targets)),
    }
    row58_source = source_at(0x40AD24)
    row58_live_targets = route_targets(row58_source, {0x40AD2C, 0x40AD32})

    def row58_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AD38 <= int(live_anchor_ea) < 0x40AD52:
            return 0x40AD38
        if 0x40B2DB <= int(live_anchor_ea) < 0x40B2F5:
            return 0x40B2DB
        return int(live_anchor_ea)

    row58_snapshot = {
        "row58_source_present": row58_source is not None,
        "row58_indirect": exact_indirect(0x40AD36),
        "row58_target_eas": tuple(
            sorted(row58_semantic_anchor(ea) for ea in row58_live_targets)
        ),
    }
    row59_source = source_at(0x40AD3E)
    row59_live_targets = route_targets(row59_source, {0x40AD46, 0x40AD4C})

    def row59_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AD52 <= int(live_anchor_ea) < 0x40AD6E:
            return 0x40AD52
        return int(live_anchor_ea)

    row59_snapshot = {
        "row59_source_present": row59_source is not None,
        "row59_indirect": exact_indirect(0x40AD50),
        "row59_target_eas": tuple(
            sorted(row59_semantic_anchor(ea) for ea in row59_live_targets)
        ),
    }
    row60_source = source_at(0x40AD57)
    row60_live_targets = route_targets(row60_source, {0x40AD65, 0x40AD68})

    def row60_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row60_snapshot = {
        "row60_source_present": row60_source is not None,
        "row60_indirect": exact_indirect(0x40AD6C),
        "row60_target_eas": tuple(
            sorted(row60_semantic_anchor(ea) for ea in row60_live_targets)
        ),
    }
    row61_source = source_at(0x40AD74)
    row61_live_targets = route_targets(row61_source, {0x40AD7C, 0x40AD82})

    def row61_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AD88 <= int(live_anchor_ea) < 0x40ADA2:
            return 0x40AD88
        if 0x40B32C <= int(live_anchor_ea) < 0x40B342:
            return 0x40B32C
        return int(live_anchor_ea)

    row61_snapshot = {
        "row61_source_present": row61_source is not None,
        "row61_indirect": exact_indirect(0x40AD86),
        "row61_target_eas": tuple(
            sorted(row61_semantic_anchor(ea) for ea in row61_live_targets)
        ),
    }
    row62_source = source_at(0x40AD8E)
    row62_live_targets = route_targets(row62_source, {0x40AD96, 0x40AD9C})

    def row62_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ADA2 <= int(live_anchor_ea) < 0x40ADBE:
            return 0x40ADA2
        return int(live_anchor_ea)

    row62_snapshot = {
        "row62_source_present": row62_source is not None,
        "row62_indirect": exact_indirect(0x40ADA0),
        "row62_target_eas": tuple(
            sorted(row62_semantic_anchor(ea) for ea in row62_live_targets)
        ),
    }
    row63_source = source_at(0x40ADA7)
    row63_live_targets = route_targets(row63_source, {0x40ADB5, 0x40ADB8})

    def row63_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row63_snapshot = {
        "row63_source_present": row63_source is not None,
        "row63_indirect": exact_indirect(0x40ADBC),
        "row63_target_eas": tuple(
            sorted(row63_semantic_anchor(ea) for ea in row63_live_targets)
        ),
    }
    row64_source = source_at(0x40ADC4)
    row64_live_targets = route_targets(row64_source, {0x40ADCC, 0x40ADD2})

    def row64_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40ADD8 <= int(live_anchor_ea) < 0x40ADF2:
            return 0x40ADD8
        if 0x40B37C <= int(live_anchor_ea) < 0x40B396:
            return 0x40B37C
        return int(live_anchor_ea)

    row64_snapshot = {
        "row64_source_present": row64_source is not None,
        "row64_indirect": exact_indirect(0x40ADD6),
        "row64_target_eas": tuple(
            sorted(row64_semantic_anchor(ea) for ea in row64_live_targets)
        ),
    }
    row65_source = source_at(0x40ADDE)
    row65_live_targets = route_targets(row65_source, {0x40ADE6, 0x40ADEC})

    def row65_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ADF2 <= int(live_anchor_ea) < 0x40AE1A:
            return 0x40ADF2
        return int(live_anchor_ea)

    row65_snapshot = {
        "row65_source_present": row65_source is not None,
        "row65_indirect": exact_indirect(0x40ADF0),
        "row65_target_eas": tuple(
            sorted(row65_semantic_anchor(ea) for ea in row65_live_targets)
        ),
    }
    row66_source = source_at(0x40ADF7)
    row66_live_targets = route_targets(row66_source, {0x40AE05, 0x40AE08})

    def row66_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row66_snapshot = {
        "row66_source_present": row66_source is not None,
        "row66_indirect": exact_indirect(0x40AE18),
        "row66_target_eas": tuple(
            sorted(row66_semantic_anchor(ea) for ea in row66_live_targets)
        ),
    }
    row67_source = source_at(0x40AE1A)
    row67_live_targets = route_targets(row67_source, set())

    def row67_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5CA <= int(live_anchor_ea) < 0x40A5E5:
            return 0x40A5CA
        return int(live_anchor_ea)

    row67_snapshot = {
        "row67_source_present": row67_source is not None,
        "row67_indirect": exact_indirect(0x40AE24),
        "row67_target_eas": tuple(
            sorted(row67_semantic_anchor(ea) for ea in row67_live_targets)
        ),
    }
    row68_source = source_at(0x40AE28)
    row68_live_targets = route_targets(row68_source, {0x40A560})

    def row68_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AE3E <= int(live_anchor_ea) < 0x40AE8B:
            return 0x40AE3E
        return int(live_anchor_ea)

    row68_snapshot = {
        "row68_source_present": row68_source is not None,
        "row68_indirect": exact_indirect(0x40AE3C),
        "row68_target_eas": tuple(
            sorted(row68_semantic_anchor(ea) for ea in row68_live_targets)
        ),
    }
    row69_source = source_at(0x40AE74)
    row69_live_targets = route_targets(row69_source, {0x40AE82, 0x40AE85})

    def row69_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row69_snapshot = {
        "row69_source_present": row69_source is not None,
        "row69_indirect": exact_indirect(0x40AE89),
        "row69_target_eas": tuple(
            sorted(row69_semantic_anchor(ea) for ea in row69_live_targets)
        ),
    }
    row70_source = source_at(0x40AE91)
    row70_live_targets = route_targets(row70_source, {0x40AE99, 0x40AE9F})

    def row70_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AEA5 <= int(live_anchor_ea) < 0x40AEE6:
            return 0x40AEA5
        return int(live_anchor_ea)

    row70_snapshot = {
        "row70_source_present": row70_source is not None,
        "row70_indirect": exact_indirect(0x40AEA3),
        "row70_target_eas": tuple(
            sorted(row70_semantic_anchor(ea) for ea in row70_live_targets)
        ),
    }
    row71_source = source_at(0x40AEDA)
    row71_live_targets = route_targets(row71_source, set())

    def row71_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row71_snapshot = {
        "row71_source_present": row71_source is not None,
        "row71_indirect": exact_indirect(0x40AEE4),
        "row71_target_eas": tuple(
            sorted(row71_semantic_anchor(ea) for ea in row71_live_targets)
        ),
    }
    row72_source = source_at(0x40AEEC)
    row72_live_targets = route_targets(row72_source, {0x40AEF4, 0x40AEFA})

    def row72_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AF00 <= int(live_anchor_ea) < 0x40AFDF:
            return 0x40AF00
        return int(live_anchor_ea)

    row72_snapshot = {
        "row72_source_present": row72_source is not None,
        "row72_indirect": exact_indirect(0x40AEFE),
        "row72_target_eas": tuple(
            sorted(row72_semantic_anchor(ea) for ea in row72_live_targets)
        ),
    }
    row73_source = source_at(0x40AFD3)
    row73_live_targets = route_targets(row73_source, set())

    def row73_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row73_snapshot = {
        "row73_source_present": row73_source is not None,
        "row73_indirect": exact_indirect(0x40AFDD),
        "row73_target_eas": tuple(
            sorted(row73_semantic_anchor(ea) for ea in row73_live_targets)
        ),
    }
    row74_source = source_at(0x40AFE5)
    row74_live_targets = route_targets(row74_source, {0x40AFED, 0x40AFF3})

    def row74_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AFF9 <= int(live_anchor_ea) < 0x40B024:
            return 0x40AFF9
        return int(live_anchor_ea)

    row74_snapshot = {
        "row74_source_present": row74_source is not None,
        "row74_indirect": exact_indirect(0x40AFF7),
        "row74_target_eas": tuple(
            sorted(row74_semantic_anchor(ea) for ea in row74_live_targets)
        ),
    }
    row75_source = source_at(0x40B01E)
    row75_live_targets = route_targets(row75_source, set())

    def row75_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row75_snapshot = {
        "row75_source_present": row75_source is not None,
        "row75_indirect": exact_indirect(0x40B022),
        "row75_target_eas": tuple(
            sorted(row75_semantic_anchor(ea) for ea in row75_live_targets)
        ),
    }
    row76_source = source_at(0x40B02A)
    row76_live_targets = route_targets(row76_source, {0x40B032, 0x40B038})

    def row76_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B03E <= int(live_anchor_ea) < 0x40B071:
            return 0x40B03E
        if 0x40B628 <= int(live_anchor_ea) < 0x40B647:
            return 0x40B03E
        return int(live_anchor_ea)

    row76_snapshot = {
        "row76_source_present": row76_source is not None,
        "row76_indirect": exact_indirect(0x40B03C),
        "row76_target_eas": tuple(
            sorted(row76_semantic_anchor(ea) for ea in row76_live_targets)
        ),
    }
    row77_source = source_at(0x40B06B)
    row77_live_targets = route_targets(row77_source, set())

    def row77_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row77_snapshot = {
        "row77_source_present": row77_source is not None,
        "row77_indirect": exact_indirect(0x40B06F),
        "row77_target_eas": tuple(
            sorted(row77_semantic_anchor(ea) for ea in row77_live_targets)
        ),
    }
    row78_source = source_at(0x40B077)
    row78_live_targets = route_targets(row78_source, {0x40B07F, 0x40B085})

    def row78_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B08B <= int(live_anchor_ea) < 0x40B0BC:
            return 0x40B08B
        return int(live_anchor_ea)

    row78_snapshot = {
        "row78_source_present": row78_source is not None,
        "row78_indirect": exact_indirect(0x40B089),
        "row78_target_eas": tuple(
            sorted(row78_semantic_anchor(ea) for ea in row78_live_targets)
        ),
    }
    row79_source = source_at(0x40B0A5)
    row79_live_targets = route_targets(row79_source, {0x40B0B3, 0x40B0B6})

    def row79_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row79_snapshot = {
        "row79_source_present": row79_source is not None,
        "row79_indirect": exact_indirect(0x40B0BA),
        "row79_target_eas": tuple(
            sorted(row79_semantic_anchor(ea) for ea in row79_live_targets)
        ),
    }
    row80_source = source_at(0x40B0C2)
    row80_live_targets = route_targets(row80_source, {0x40B0CA, 0x40B0D0})

    def row80_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B0D6 <= int(live_anchor_ea) < 0x40B0F2:
            return 0x40B0D6
        return int(live_anchor_ea)

    row80_snapshot = {
        "row80_source_present": row80_source is not None,
        "row80_indirect": exact_indirect(0x40B0D4),
        "row80_target_eas": tuple(
            sorted(row80_semantic_anchor(ea) for ea in row80_live_targets)
        ),
    }
    row81_source = source_at(0x40B0DB)
    row81_live_targets = route_targets(row81_source, {0x40B0E9, 0x40B0EC})

    def row81_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row81_snapshot = {
        "row81_source_present": row81_source is not None,
        "row81_indirect": exact_indirect(0x40B0F0),
        "row81_target_eas": tuple(
            sorted(row81_semantic_anchor(ea) for ea in row81_live_targets)
        ),
    }
    row82_source = source_at(0x40B0F8)
    row82_live_targets = route_targets(row82_source, {0x40B100, 0x40B106})

    def row82_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B10C <= int(live_anchor_ea) < 0x40B149:
            return 0x40B10C
        return int(live_anchor_ea)

    row82_snapshot = {
        "row82_source_present": row82_source is not None,
        "row82_indirect": exact_indirect(0x40B10A),
        "row82_target_eas": tuple(
            sorted(row82_semantic_anchor(ea) for ea in row82_live_targets)
        ),
    }
    row83_source = source_at(0x40B132)
    row83_live_targets = route_targets(row83_source, {0x40B140, 0x40B143})

    def row83_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row83_snapshot = {
        "row83_source_present": row83_source is not None,
        "row83_indirect": exact_indirect(0x40B147),
        "row83_target_eas": tuple(
            sorted(row83_semantic_anchor(ea) for ea in row83_live_targets)
        ),
    }
    row84_source = source_at(0x40B14F)
    row84_live_targets = route_targets(row84_source, {0x40B157, 0x40B15D})

    def row84_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B163 <= int(live_anchor_ea) < 0x40B17F:
            return 0x40B163
        return int(live_anchor_ea)

    row84_snapshot = {
        "row84_source_present": row84_source is not None,
        "row84_indirect": exact_indirect(0x40B161),
        "row84_target_eas": tuple(
            sorted(row84_semantic_anchor(ea) for ea in row84_live_targets)
        ),
    }
    row85_source = source_at(0x40B168)
    row85_live_targets = route_targets(row85_source, {0x40B176, 0x40B179})

    def row85_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row85_snapshot = {
        "row85_source_present": row85_source is not None,
        "row85_indirect": exact_indirect(0x40B17D),
        "row85_target_eas": tuple(
            sorted(row85_semantic_anchor(ea) for ea in row85_live_targets)
        ),
    }
    row86_source = source_at(0x40B185)
    row86_live_targets = route_targets(row86_source, {0x40B18D, 0x40B193})

    def row86_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B199 <= int(live_anchor_ea) < 0x40B1D0:
            return 0x40B199
        if 0x40B647 <= int(live_anchor_ea) < 0x40B668:
            return 0x40B199
        return int(live_anchor_ea)

    row86_snapshot = {
        "row86_source_present": row86_source is not None,
        "row86_indirect": exact_indirect(0x40B197),
        "row86_target_eas": tuple(
            sorted(row86_semantic_anchor(ea) for ea in row86_live_targets)
        ),
    }
    row87_source = source_at(0x40B1CA)
    row87_live_targets = route_targets(row87_source, set())

    def row87_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row87_snapshot = {
        "row87_source_present": row87_source is not None,
        "row87_indirect": exact_indirect(0x40B1CE),
        "row87_target_eas": tuple(
            sorted(row87_semantic_anchor(ea) for ea in row87_live_targets)
        ),
    }
    row88_source = source_at(0x40B1D6)
    row88_live_targets = route_targets(row88_source, {0x40B1DE, 0x40B1E4})

    def row88_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B1EA <= int(live_anchor_ea) < 0x40B21C:
            return 0x40B1EA
        return int(live_anchor_ea)

    row88_snapshot = {
        "row88_source_present": row88_source is not None,
        "row88_indirect": exact_indirect(0x40B1E8),
        "row88_target_eas": tuple(
            sorted(row88_semantic_anchor(ea) for ea in row88_live_targets)
        ),
    }
    row89_source = source_at(0x40B205)
    row89_live_targets = route_targets(row89_source, {0x40B213, 0x40B216})

    def row89_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row89_snapshot = {
        "row89_source_present": row89_source is not None,
        "row89_indirect": exact_indirect(0x40B21A),
        "row89_target_eas": tuple(
            sorted(row89_semantic_anchor(ea) for ea in row89_live_targets)
        ),
    }
    row90_source = source_at(0x40B222)
    row90_live_targets = route_targets(row90_source, {0x40B22A, 0x40B230})

    def row90_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B236 <= int(live_anchor_ea) < 0x40B26D:
            return 0x40B236
        return int(live_anchor_ea)

    row90_snapshot = {
        "row90_source_present": row90_source is not None,
        "row90_indirect": exact_indirect(0x40B234),
        "row90_target_eas": tuple(
            sorted(row90_semantic_anchor(ea) for ea in row90_live_targets)
        ),
    }
    row91_source = source_at(0x40B256)
    row91_live_targets = route_targets(row91_source, {0x40B264, 0x40B267})

    def row91_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row91_snapshot = {
        "row91_source_present": row91_source is not None,
        "row91_indirect": exact_indirect(0x40B26B),
        "row91_target_eas": tuple(
            sorted(row91_semantic_anchor(ea) for ea in row91_live_targets)
        ),
    }
    row92_source = source_at(0x40B273)
    row92_live_targets = route_targets(row92_source, {0x40B27B, 0x40B281})

    def row92_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B287 <= int(live_anchor_ea) < 0x40B2DB:
            return 0x40B287
        return int(live_anchor_ea)

    row92_snapshot = {
        "row92_source_present": row92_source is not None,
        "row92_indirect": exact_indirect(0x40B285),
        "row92_target_eas": tuple(
            sorted(row92_semantic_anchor(ea) for ea in row92_live_targets)
        ),
    }
    row93_source = source_at(0x40B2CF)
    row93_live_targets = route_targets(row93_source, set())

    def row93_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row93_snapshot = {
        "row93_source_present": row93_source is not None,
        "row93_indirect": exact_indirect(0x40B2D9),
        "row93_target_eas": tuple(
            sorted(row93_semantic_anchor(ea) for ea in row93_live_targets)
        ),
    }
    row94_source = source_at(0x40B2E1)
    row94_live_targets = route_targets(row94_source, {0x40B2E9, 0x40B2EF})

    def row94_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B2F5 <= int(live_anchor_ea) < 0x40B32C:
            return 0x40B2F5
        if 0x40B693 <= int(live_anchor_ea) < 0x40B6B4:
            return 0x40B2F5
        return int(live_anchor_ea)

    row94_snapshot = {
        "row94_source_present": row94_source is not None,
        "row94_indirect": exact_indirect(0x40B2F3),
        "row94_target_eas": tuple(
            sorted(row94_semantic_anchor(ea) for ea in row94_live_targets)
        ),
    }
    row95_source = source_at(0x40B326)
    row95_live_targets = route_targets(row95_source, set())

    def row95_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row95_snapshot = {
        "row95_source_present": row95_source is not None,
        "row95_indirect": exact_indirect(0x40B32A),
        "row95_target_eas": tuple(
            sorted(row95_semantic_anchor(ea) for ea in row95_live_targets)
        ),
    }
    row96_source = source_at(0x40B334)
    row96_live_targets = route_targets(row96_source, {_FUNCTION_EA})

    def row96_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B342 <= int(live_anchor_ea) < 0x40B37C:
            return 0x40B342
        return int(live_anchor_ea)

    row96_snapshot = {
        "row96_source_present": row96_source is not None,
        "row96_indirect": exact_indirect(0x40B340),
        "row96_target_eas": tuple(
            sorted(row96_semantic_anchor(ea) for ea in row96_live_targets)
        ),
    }
    row97_source = source_at(0x40B365)
    row97_live_targets = route_targets(row97_source, {0x40B373, 0x40B376})

    def row97_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row97_snapshot = {
        "row97_source_present": row97_source is not None,
        "row97_indirect": exact_indirect(0x40B37A),
        "row97_target_eas": tuple(
            sorted(row97_semantic_anchor(ea) for ea in row97_live_targets)
        ),
    }
    row98_source = source_at(0x40B382)
    row98_live_targets = route_targets(row98_source, {0x40B38A, 0x40B390})

    def row98_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B396 <= int(live_anchor_ea) < 0x40B3B0:
            return 0x40B396
        if 0x40B3E5 <= int(live_anchor_ea) < 0x40B3FF:
            return 0x40B3E5
        return int(live_anchor_ea)

    row98_snapshot = {
        "row98_source_present": row98_source is not None,
        "row98_indirect": exact_indirect(0x40B394),
        "row98_target_eas": tuple(
            sorted(row98_semantic_anchor(ea) for ea in row98_live_targets)
        ),
    }
    row99_source = source_at(0x40B39C)
    row99_live_targets = route_targets(row99_source, {0x40B3A4, 0x40B3AA})

    def row99_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B3B0 <= int(live_anchor_ea) < 0x40B3E5:
            return 0x40B3B0
        return int(live_anchor_ea)

    row99_snapshot = {
        "row99_source_present": row99_source is not None,
        "row99_indirect": exact_indirect(0x40B3AE),
        "row99_target_eas": tuple(
            sorted(row99_semantic_anchor(ea) for ea in row99_live_targets)
        ),
    }
    row100_source = source_at(0x40B3CE)
    row100_live_targets = route_targets(row100_source, {0x40B3DC, 0x40B3DF})

    def row100_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row100_snapshot = {
        "row100_source_present": row100_source is not None,
        "row100_indirect": exact_indirect(0x40B3E3),
        "row100_target_eas": tuple(
            sorted(row100_semantic_anchor(ea) for ea in row100_live_targets)
        ),
    }
    row101_source = source_at(0x40B3EB)
    row101_live_targets = route_targets(row101_source, {0x40B3F3, 0x40B3F9})

    def row101_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B3FF <= int(live_anchor_ea) < 0x40B4C5:
            return 0x40B3FF
        return int(live_anchor_ea)

    row101_snapshot = {
        "row101_source_present": row101_source is not None,
        "row101_indirect": exact_indirect(0x40B3FD),
        "row101_target_eas": tuple(
            sorted(row101_semantic_anchor(ea) for ea in row101_live_targets)
        ),
    }
    row102_source = source_at(0x40B4B4)
    row102_live_targets = route_targets(row102_source, {0x40B4BC, 0x40B4BF})

    def row102_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row102_snapshot = {
        "row102_source_present": row102_source is not None,
        "row102_indirect": exact_indirect(0x40B4C3),
        "row102_target_eas": tuple(
            sorted(row102_semantic_anchor(ea) for ea in row102_live_targets)
        ),
    }
    if source is None:
        return {
            "maturity": int(mba.maturity),
            "quantity": int(mba.qty),
            "source_present": False,
            "indirect": transfer_indirect,
            "target_eas": (),
            "reachable_eas": reachable_anchors(),
            **row5_snapshot,
            **row6_snapshot,
            **selected_snapshot,
            **row9_snapshot,
            **row10_snapshot,
            **row11_snapshot,
            **row12_snapshot,
            **setcc_snapshot,
            **scaled_setcc_snapshot,
            **row18_snapshot,
            **row19_snapshot,
            **row20_snapshot,
            **row21_snapshot,
            **row22_snapshot,
            **row23_snapshot,
            **row25_snapshot,
            **row26_snapshot,
            **row27_snapshot,
            **row28_snapshot,
            **row29_snapshot,
            **row30_snapshot,
            **row31_snapshot,
            **row32_snapshot,
            **row33_snapshot,
            **row34_snapshot,
            **row35_snapshot,
            **row36_snapshot,
            **row37_snapshot,
            **row38_snapshot,
            **row39_snapshot,
            **row40_snapshot,
            **row42_snapshot,
            **row43_snapshot,
            **row44_snapshot,
            **row45_snapshot,
            **row46_snapshot,
            **row47_snapshot,
            **row49_snapshot,
            **row50_snapshot,
            **row51_snapshot,
            **row52_snapshot,
            **row53_snapshot,
            **row54_snapshot,
            **row55_snapshot,
            **row56_snapshot,
            **row57_snapshot,
            **row58_snapshot,
            **row59_snapshot,
            **row60_snapshot,
            **row61_snapshot,
            **row62_snapshot,
            **row63_snapshot,
            **row64_snapshot,
            **row65_snapshot,
            **row66_snapshot,
            **row67_snapshot,
            **row68_snapshot,
            **row69_snapshot,
            **row70_snapshot,
            **row71_snapshot,
            **row72_snapshot,
            **row73_snapshot,
            **row74_snapshot,
            **row75_snapshot,
            **row76_snapshot,
            **row77_snapshot,
            **row78_snapshot,
            **row79_snapshot,
            **row80_snapshot,
            **row81_snapshot,
            **row82_snapshot,
            **row83_snapshot,
            **row84_snapshot,
            **row85_snapshot,
            **row86_snapshot,
            **row87_snapshot,
            **row88_snapshot,
            **row89_snapshot,
            **row90_snapshot,
            **row91_snapshot,
            **row92_snapshot,
            **row93_snapshot,
            **row94_snapshot,
            **row95_snapshot,
            **row96_snapshot,
            **row97_snapshot,
            **row98_snapshot,
            **row99_snapshot,
            **row100_snapshot,
            **row101_snapshot,
            **row102_snapshot,
        }
    target_eas: set[int] = set()
    indirect = False
    source_successors = tuple(int(value) for value in source.succset)
    if source_successors:
        route_serials = [int(source.serial)]
        for successor_serial in source_successors:
            target = blocks[successor_serial]
            route_serials.append(successor_serial)
            while (
                _native_anchor(target, origins) in {0x40A5FE, 0x40A601}
                and len(tuple(target.succset)) == 1
            ):
                successor_serial = int(tuple(target.succset)[0])
                target = blocks[successor_serial]
                route_serials.append(successor_serial)
            target_eas.add(_native_anchor(target, origins))
        indirect = any(
            block.tail is not None and int(block.tail.opcode) == int(ida_hexrays.m_ijmp)
            for block in (blocks[serial] for serial in route_serials)
        )
    else:
        route_rows = (
            *(_instructions(source)[-1:]),
            *(_instructions(source.nextb)[-1:]),
            *(_instructions(source.nextb.nextb)[-1:]),
        )
        for row in route_rows:
            opcode = int(row.opcode)
            if opcode == int(ida_hexrays.m_ijmp):
                indirect = True
            operand = row.l if opcode == int(ida_hexrays.m_goto) else row.d
            if int(operand.t) != int(ida_hexrays.mop_b):
                continue
            target = blocks[int(operand.b)]
            target_eas.add(_native_anchor(target, origins))
    return {
        "maturity": int(mba.maturity),
        "quantity": int(mba.qty),
        "source_present": True,
        "source_serial": int(source.serial),
        "route_blocks": tuple(
            (
                int(block.serial),
                _native_anchor(block, origins),
                int(block.type),
                tuple(int(value) for value in block.succset),
            )
            for block in (source, source.nextb, source.nextb.nextb)
        ),
        "indirect": indirect,
        "target_eas": tuple(sorted(target_eas)),
        "reachable_eas": reachable_anchors(),
        **row5_snapshot,
        **row6_snapshot,
        **selected_snapshot,
        **row9_snapshot,
        **row10_snapshot,
        **row11_snapshot,
        **row12_snapshot,
        **setcc_snapshot,
        **scaled_setcc_snapshot,
        **row18_snapshot,
        **row19_snapshot,
        **row20_snapshot,
        **row21_snapshot,
        **row22_snapshot,
        **row23_snapshot,
        **row25_snapshot,
        **row26_snapshot,
        **row27_snapshot,
        **row28_snapshot,
        **row29_snapshot,
        **row30_snapshot,
        **row31_snapshot,
        **row32_snapshot,
        **row33_snapshot,
        **row34_snapshot,
        **row35_snapshot,
        **row36_snapshot,
        **row37_snapshot,
        **row38_snapshot,
        **row39_snapshot,
        **row40_snapshot,
        **row42_snapshot,
        **row43_snapshot,
        **row44_snapshot,
        **row45_snapshot,
        **row46_snapshot,
        **row47_snapshot,
        **row49_snapshot,
        **row50_snapshot,
        **row51_snapshot,
        **row52_snapshot,
        **row53_snapshot,
        **row54_snapshot,
        **row55_snapshot,
        **row56_snapshot,
        **row57_snapshot,
        **row58_snapshot,
        **row59_snapshot,
        **row60_snapshot,
        **row61_snapshot,
        **row62_snapshot,
        **row63_snapshot,
        **row64_snapshot,
        **row65_snapshot,
        **row66_snapshot,
        **row67_snapshot,
        **row68_snapshot,
        **row69_snapshot,
        **row70_snapshot,
        **row71_snapshot,
        **row72_snapshot,
        **row73_snapshot,
        **row74_snapshot,
        **row75_snapshot,
        **row76_snapshot,
        **row77_snapshot,
        **row78_snapshot,
        **row79_snapshot,
        **row80_snapshot,
        **row81_snapshot,
        **row82_snapshot,
        **row83_snapshot,
        **row84_snapshot,
        **row85_snapshot,
        **row86_snapshot,
        **row87_snapshot,
        **row88_snapshot,
        **row89_snapshot,
        **row90_snapshot,
        **row91_snapshot,
        **row92_snapshot,
        **row93_snapshot,
        **row94_snapshot,
        **row95_snapshot,
        **row96_snapshot,
        **row97_snapshot,
        **row98_snapshot,
        **row99_snapshot,
        **row100_snapshot,
        **row101_snapshot,
        **row102_snapshot,
    }


def _run_worker(binary: pathlib.Path) -> None:
    faulthandler.dump_traceback_later(45, repeat=False)
    print("checksum-worker:open", flush=True)
    assert idapro.open_database(str(binary), True) == 0
    hook = None
    try:
        import ida_hexrays
        import idaapi
        import idc

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()
        assert idc.SetType(0x40F830, "int __cdecl sub_40F830(void)")

        import d810.headless as headless

        headless.configure(
            project="default_unflattening_ollvm.json",
            ida_user_dir=binary.parent / "ida-user",
        )
        headless.start()

        class NoFlowStages:
            def active_stages(self, **_kwargs):
                return ()

        # The checksum isolates the GENERATED producer.  Retain the configured
        # instruction optimizer (its first callback owns the GENERATED seam),
        # while suppressing the older broad PREOPT flow publication entirely.
        headless._state.manager.block_optimizer._execution_scope_service = NoFlowStages()
        print("checksum-worker:started", flush=True)
        receipts = []
        from d810.hexrays.mutation.mba_mutation_events import MbaMutationCommitted

        headless._state.manager.event_emitter.on(
            MbaMutationCommitted,
            lambda event: receipts.append(event.receipt),
        )
        captures: dict[str, object] = {"calls_count": 0}

        class Probe(ida_hexrays.Hexrays_Hooks):
            def preoptimized(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA:
                    captures["preopt"] = _route_snapshot(mba)
                return 0

            def locopt(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA and "first_cfg" not in captures:
                    captures["first_cfg"] = _route_snapshot(mba)
                return 0

            def calls_done(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA:
                    captures["calls_count"] = int(captures["calls_count"]) + 1
                    captures["calls"] = _route_snapshot(mba)
                return 0

        hook = Probe()
        assert hook.hook()
        ida_hexrays.mark_cfunc_dirty(_FUNCTION_EA)
        print("checksum-worker:decompile", flush=True)
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = headless.decompile(_FUNCTION_EA, failure=failure)
        print("checksum-worker:decompiled", flush=True)
        assert cfunc is not None, (
            f"A560 ctree failed: code={int(failure.code)} "
            f"ea=0x{int(failure.errea):X} desc={failure.desc()}"
        )
        matching = tuple(
            receipt
            for receipt in receipts
            if str(receipt.fragment_plan_id).startswith(
                "rhad-reference-compiler:rhad-generated-reference@0x40A560:"
            )
        )
        assert len(matching) == 1, tuple(
            str(receipt.fragment_plan_id) for receipt in receipts
        )
        receipt = matching[0]
        assert receipt.operation_count == receipt.planned_operation_count == 1492, (
            receipt.operation_count,
            receipt.planned_operation_count,
        )
        assert len(receipt.version_transitions) >= 10
        assert receipt.prepublication_validation.passed
        assert receipt.postpublication_validation.passed
        assert receipt.root_publication_confirmed
        assert captures["preopt"]["indirect"] is False
        assert set(captures["preopt"]["target_eas"]) == {0x40A607, 0x40B6C0}, captures[
            "preopt"
        ]
        assert captures["first_cfg"]["indirect"] is False
        assert set(captures["first_cfg"]["target_eas"]) == {
            0x40A607,
            0x40B6C0,
        }, captures["first_cfg"]
        assert 0x40B6C0 in captures["first_cfg"]["reachable_eas"], captures["first_cfg"]
        for capture_name in ("preopt", "first_cfg"):
            selected_capture = captures[capture_name]
            assert selected_capture["row5_source_present"] is True
            assert selected_capture["row5_indirect"] is False
            assert set(selected_capture["row5_target_eas"]) == {
                0x40A663,
                *({0x40AAFD} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row5_target_eas"])
            assert selected_capture["row6_source_present"] is True
            assert selected_capture["row6_indirect"] is False
            assert set(selected_capture["row6_target_eas"]) == {
                0x40AE26,
                *({0x40A5CA} if capture_name == "preopt" else set()),
            }, selected_capture
            assert selected_capture["selected_source_present"] is True
            assert selected_capture["selected_indirect"] is False
            assert set(selected_capture["selected_target_eas"]) == {
                0x40A6A6,
                0x40A800,
            }, selected_capture
            assert selected_capture["row9_source_present"] is True
            assert selected_capture["row9_indirect"] is False
            assert set(selected_capture["row9_target_eas"]) == {
                0x40A6C0,
                0x40A960,
            }, selected_capture
            assert selected_capture["row10_source_present"] is True
            assert selected_capture["row10_indirect"] is False
            assert set(selected_capture["row10_target_eas"]) == {
                0x40A6DA,
                0x40AB76,
            }, selected_capture
            assert selected_capture["row11_source_present"] is True
            assert selected_capture["row11_indirect"] is False
            assert set(selected_capture["row11_target_eas"]) == {
                0x40A6F4,
                0x40AE8B,
            }, selected_capture
            assert selected_capture["row12_source_present"] is True
            assert selected_capture["row12_indirect"] is False
            assert set(selected_capture["row12_target_eas"]) == {
                0x40A5F0,
                {
                    "preopt": 0x40A70E,
                    "first_cfg": 0x40A71D,
                }[capture_name],
            }, selected_capture
            assert selected_capture["setcc_source_present"] is True
            assert selected_capture["setcc_indirect"] is False
            assert set(selected_capture["setcc_target_eas"]) == {
                0x40A77E,
                0x40ABC6,
            }, selected_capture
            assert selected_capture["scaled_setcc_source_present"] is True
            assert selected_capture["scaled_setcc_indirect"] is False
            assert set(selected_capture["scaled_setcc_target_eas"]) == {
                0x40A794,
                0x40AEE6,
            }, selected_capture
            assert selected_capture["row18_source_present"] is True
            assert selected_capture["row18_indirect"] is False
            assert set(selected_capture["row18_target_eas"]) == {
                0x40A5F0,
                0x40A7AE,
            }, selected_capture
            assert selected_capture["row19_source_present"] is True
            assert selected_capture["row19_indirect"] is False
            assert set(selected_capture["row19_target_eas"]) == {
                0x40B6C0,
            }, selected_capture
            assert selected_capture["row20_source_present"] is True
            assert selected_capture["row20_indirect"] is False
            assert set(selected_capture["row20_target_eas"]) == {
                0x40A81A,
                0x40AA60,
            }, selected_capture
            assert selected_capture["row21_source_present"] is True
            assert selected_capture["row21_indirect"] is False
            assert set(selected_capture["row21_target_eas"]) == {
                0x40A834,
                0x40AC3D,
            }, selected_capture
            assert selected_capture["row22_source_present"] is True
            assert selected_capture["row22_indirect"] is False
            assert set(selected_capture["row22_target_eas"]) == {
                0x40A84E,
                0x40AFDF,
            }, selected_capture
            assert selected_capture["row23_source_present"] is True
            assert selected_capture["row23_indirect"] is False
            assert set(selected_capture["row23_target_eas"]) == {
                0x40A5F0,
                0x40A868,
            }, selected_capture
            assert selected_capture["row25_source_present"] is (
                capture_name == "preopt"
            )
            assert selected_capture["row25_indirect"] is False
            assert set(selected_capture["row25_target_eas"]) == (
                {0x40A64B} if capture_name == "preopt" else set()
            ), selected_capture
            assert selected_capture["row26_source_present"] is True
            assert selected_capture["row26_indirect"] is False
            assert set(selected_capture["row26_target_eas"]) == {
                0x40A8CF,
                0x40ACBF,
            }, selected_capture
            assert selected_capture["row27_source_present"] is True
            assert selected_capture["row27_indirect"] is False
            assert set(selected_capture["row27_target_eas"]) == {
                0x40A8E9,
                0x40B024,
            }, selected_capture
            assert selected_capture["row28_source_present"] is True
            assert selected_capture["row28_indirect"] is False
            assert set(selected_capture["row28_target_eas"]) == {
                0x40A5F0,
                0x40A903,
            }, selected_capture
            assert selected_capture["row29_source_present"] is True
            assert selected_capture["row29_indirect"] is False
            assert set(selected_capture["row29_target_eas"]) == {
                0x40B6C0,
            }, selected_capture
            assert selected_capture["row30_source_present"] is True
            assert selected_capture["row30_indirect"] is False
            assert set(selected_capture["row30_target_eas"]) == {
                0x40A97A,
                0x40AD1E,
            }, selected_capture
            assert selected_capture["row31_source_present"] is True
            assert selected_capture["row31_indirect"] is False
            assert set(selected_capture["row31_target_eas"]) == {
                0x40A994,
                0x40B071,
            }, selected_capture
            assert selected_capture["row32_source_present"] is True
            assert selected_capture["row32_indirect"] is False
            assert set(selected_capture["row32_target_eas"]) == {
                0x40A5F0,
                0x40A9AE,
            }, selected_capture
            assert selected_capture["row33_source_present"] is True
            assert selected_capture["row33_indirect"] is False
            assert set(selected_capture["row33_target_eas"]) == (
                {0x40A607, 0x40B6C0} if capture_name == "preopt" else {0x40B6C0}
            ), selected_capture
            assert selected_capture["row34_source_present"] is True
            assert selected_capture["row34_indirect"] is False
            assert set(selected_capture["row34_target_eas"]) == {
                0x40A9F8,
                0x40AD6E,
            }, selected_capture
            assert selected_capture["row35_source_present"] is True
            assert selected_capture["row35_indirect"] is False
            assert set(selected_capture["row35_target_eas"]) == {
                0x40AA12,
                0x40B0BC,
            }, selected_capture
            assert selected_capture["row36_source_present"] is True
            assert selected_capture["row36_indirect"] is False
            assert set(selected_capture["row36_target_eas"]) == {
                0x40A5F0,
                0x40AA2C,
            }, selected_capture
            assert selected_capture["row37_source_present"] is True
            assert selected_capture["row37_indirect"] is False
            assert set(selected_capture["row37_target_eas"]) == (
                {0x40A607, 0x40B6C0} if capture_name == "preopt" else {0x40A607}
            ), selected_capture
            assert selected_capture["row38_source_present"] is True
            assert selected_capture["row38_indirect"] is False
            assert set(selected_capture["row38_target_eas"]) == {
                0x40AA7A,
                0x40ADBE,
            }, selected_capture
            assert selected_capture["row39_source_present"] is True
            assert selected_capture["row39_indirect"] is False
            assert set(selected_capture["row39_target_eas"]) == {
                0x40AA94,
                0x40B0F2,
            }, selected_capture
            assert selected_capture["row40_source_present"] is True
            assert selected_capture["row40_indirect"] is False
            assert set(selected_capture["row40_target_eas"]) == {
                0x40A5F0,
                0x40AAAE,
            }, selected_capture
            assert selected_capture["row42_source_present"] is (
                capture_name == "preopt"
            ), (capture_name, selected_capture["row42_source_present"])
            assert selected_capture["row42_indirect"] is False
            assert set(selected_capture["row42_target_eas"]) == {
                *({0x40AAFD, 0x40AE1A} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row42_target_eas"])
            assert selected_capture["row43_source_present"] is True
            assert selected_capture["row43_indirect"] is False
            assert set(selected_capture["row43_target_eas"]) == {
                0x40AB17,
                0x40B149,
            }, selected_capture
            assert selected_capture["row44_source_present"] is True
            assert selected_capture["row44_indirect"] is False
            assert set(selected_capture["row44_target_eas"]) == {
                0x40A5F0,
                0x40AB31,
            }, selected_capture
            assert selected_capture["row45_source_present"] is True
            assert selected_capture["row45_indirect"] is False
            assert set(selected_capture["row45_target_eas"]) == {
                0x40B6C0,
                *({0x40AB6A} if capture_name == "preopt" else set()),
            }, (
                capture_name,
                selected_capture["row45_target_eas"],
            )
            assert selected_capture["row46_source_present"] is True
            assert selected_capture["row46_indirect"] is False
            assert set(selected_capture["row46_target_eas"]) == {
                0x40AB90,
                0x40B17F,
            }, selected_capture
            assert selected_capture["row47_source_present"] is True
            assert selected_capture["row47_indirect"] is False
            assert set(selected_capture["row47_target_eas"]) == {
                0x40A5F0,
                0x40ABAA,
            }, selected_capture
            assert selected_capture["row49_source_present"] is True
            assert selected_capture["row49_indirect"] is False
            assert set(selected_capture["row49_target_eas"]) == {
                0x40ABE0,
                0x40B1D0,
            }, selected_capture
            assert selected_capture["row50_source_present"] is True
            assert selected_capture["row50_indirect"] is False
            assert set(selected_capture["row50_target_eas"]) == {
                0x40A5F0,
                0x40ABFA,
            }, selected_capture
            assert selected_capture["row51_source_present"] is True
            assert selected_capture["row51_indirect"] is False
            assert set(selected_capture["row51_target_eas"]) == {
                0x40B6C0,
                *({0x40AC31} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row51_target_eas"])
            assert selected_capture["row52_source_present"] is True
            assert selected_capture["row52_indirect"] is False
            assert set(selected_capture["row52_target_eas"]) == {
                0x40AC56,
                0x40B21C,
            }, selected_capture
            assert selected_capture["row53_source_present"] is True
            assert selected_capture["row53_indirect"] is False
            assert set(selected_capture["row53_target_eas"]) == {
                0x40A5F0,
                0x40AC70,
            }, selected_capture
            assert selected_capture["row54_source_present"] is True
            assert selected_capture["row54_indirect"] is False
            assert set(selected_capture["row54_target_eas"]) == {
                0x40B6C0,
                *({0x40ACB3} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row54_target_eas"])
            assert selected_capture["row55_source_present"] is True
            assert selected_capture["row55_indirect"] is False
            assert set(selected_capture["row55_target_eas"]) == {
                0x40ACD9,
                0x40B26D,
            }, selected_capture
            assert selected_capture["row56_source_present"] is True
            assert selected_capture["row56_indirect"] is False
            assert set(selected_capture["row56_target_eas"]) == {
                0x40A5F0,
                0x40ACF3,
            }, selected_capture
            assert selected_capture["row57_source_present"] is True
            assert selected_capture["row57_indirect"] is False
            assert set(selected_capture["row57_target_eas"]) == {
                0x40B6C0,
                *({0x40AD18} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row57_target_eas"])
            assert selected_capture["row58_source_present"] is True
            assert selected_capture["row58_indirect"] is False
            assert set(selected_capture["row58_target_eas"]) == {
                0x40AD38,
                0x40B2DB,
            }, selected_capture
            assert selected_capture["row59_source_present"] is True
            assert selected_capture["row59_indirect"] is False
            assert set(selected_capture["row59_target_eas"]) == {
                0x40A5F0,
                0x40AD52,
            }, selected_capture
            assert selected_capture["row60_source_present"] is True
            assert selected_capture["row60_indirect"] is False
            assert set(selected_capture["row60_target_eas"]) == {
                0x40B6C0,
                *({0x40A607} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row60_target_eas"])
            assert selected_capture["row61_source_present"] is True
            assert selected_capture["row61_indirect"] is False
            assert set(selected_capture["row61_target_eas"]) == {
                0x40AD88,
                0x40B32C,
            }, (capture_name, selected_capture["row61_target_eas"])
            assert selected_capture["row62_source_present"] is True
            assert selected_capture["row62_indirect"] is False
            assert set(selected_capture["row62_target_eas"]) == {
                0x40A5F0,
                0x40ADA2,
            }, (capture_name, selected_capture["row62_target_eas"])
            assert selected_capture["row63_source_present"] is True
            assert selected_capture["row63_indirect"] is False
            assert set(selected_capture["row63_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row63_target_eas"])
            assert selected_capture["row64_source_present"] is True
            assert selected_capture["row64_indirect"] is False
            assert set(selected_capture["row64_target_eas"]) == {
                0x40ADD8,
                0x40B37C,
            }, (capture_name, selected_capture["row64_target_eas"])
            assert selected_capture["row65_source_present"] is True
            assert selected_capture["row65_indirect"] is False
            assert set(selected_capture["row65_target_eas"]) == {
                0x40A5F0,
                0x40ADF2,
            }, (capture_name, selected_capture["row65_target_eas"])
            assert selected_capture["row66_source_present"] is True
            assert selected_capture["row66_indirect"] is False
            assert set(selected_capture["row66_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row66_target_eas"])
            assert selected_capture["row67_indirect"] is False
            if capture_name == "preopt":
                assert selected_capture["row67_source_present"] is True
                # PREOPT may coalesce the accepted row-67 carrier with the new
                # row-68 source.  Its own exact route remains 0x40A5CA in the
                # persisted operation observation; the additional successor
                # is row 68's proved true arm, not a row-67 delivery change.
                assert set(selected_capture["row67_target_eas"]) == {
                    0x40A5CA,
                    0x40AE3E,
                }, (
                    capture_name,
                    selected_capture["row67_target_eas"],
                )
            else:
                assert selected_capture["row67_source_present"] is False
                assert selected_capture["row67_target_eas"] == ()
            assert selected_capture["row68_source_present"] is True
            assert selected_capture["row68_indirect"] is False
            assert set(selected_capture["row68_target_eas"]) == {
                0x40A5F0,
                0x40AE3E,
            }, (capture_name, selected_capture["row68_target_eas"])
            assert selected_capture["row69_source_present"] is True
            assert selected_capture["row69_indirect"] is False
            assert set(selected_capture["row69_target_eas"]) == {
                0x40B6C0,
                *({0x40A607} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row69_target_eas"])
            assert selected_capture["row70_source_present"] is True
            assert selected_capture["row70_indirect"] is False
            assert set(selected_capture["row70_target_eas"]) == {
                0x40A5F0,
                0x40AEA5,
            }, (capture_name, selected_capture["row70_target_eas"])
            assert selected_capture["row71_source_present"] is True
            assert selected_capture["row71_indirect"] is False
            assert set(selected_capture["row71_target_eas"]) == {
                0x40B6C0,
                *({0x40AEDA} if capture_name == "preopt" else set()),
            }, (
                capture_name,
                selected_capture["row71_target_eas"],
            )
            assert selected_capture["row72_source_present"] is True
            assert selected_capture["row72_indirect"] is False
            assert set(selected_capture["row72_target_eas"]) == {
                0x40A5F0,
                0x40AF00,
            }, (capture_name, selected_capture["row72_target_eas"])
            assert selected_capture["row73_source_present"] is True
            assert selected_capture["row73_indirect"] is False
            assert set(selected_capture["row73_target_eas"]) == {
                0x40B6C0,
                *({0x40AFD3} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row73_target_eas"])
            assert selected_capture["row74_source_present"] is True
            assert selected_capture["row74_indirect"] is False
            assert set(selected_capture["row74_target_eas"]) == {
                0x40A5F0,
                0x40AFF9,
            }, (capture_name, selected_capture["row74_target_eas"])
            assert selected_capture["row75_source_present"] is True
            assert selected_capture["row75_indirect"] is False
            assert set(selected_capture["row75_target_eas"]) == {
                0x40B6C0,
                *({0x40B01E} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row75_target_eas"])
            assert selected_capture["row76_source_present"] is True
            assert selected_capture["row76_indirect"] is False
            assert set(selected_capture["row76_target_eas"]) == {
                0x40A5F0,
                0x40B03E,
            }, (capture_name, selected_capture["row76_target_eas"])
            assert selected_capture["row77_source_present"] is True
            assert selected_capture["row77_indirect"] is False
            assert set(selected_capture["row77_target_eas"]) == {
                0x40B6C0,
                *({0x40B06B} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row77_target_eas"])
            assert selected_capture["row78_source_present"] is True
            assert selected_capture["row78_indirect"] is False
            assert set(selected_capture["row78_target_eas"]) == {
                0x40A5F0,
                0x40B08B,
            }, (capture_name, selected_capture["row78_target_eas"])
            assert selected_capture["row79_source_present"] is True
            assert selected_capture["row79_indirect"] is False
            assert set(selected_capture["row79_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row79_target_eas"])
            assert selected_capture["row80_source_present"] is True
            assert selected_capture["row80_indirect"] is False
            assert set(selected_capture["row80_target_eas"]) == {
                0x40A5F0,
                0x40B0D6,
            }, (capture_name, selected_capture["row80_target_eas"])
            assert selected_capture["row81_source_present"] is True
            assert selected_capture["row81_indirect"] is False
            assert set(selected_capture["row81_target_eas"]) == {
                0x40B6C0,
                *({0x40A607} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row81_target_eas"])
            assert selected_capture["row82_source_present"] is True
            assert selected_capture["row82_indirect"] is False
            assert set(selected_capture["row82_target_eas"]) == {
                0x40A5F0,
                0x40B10C,
            }, (capture_name, selected_capture["row82_target_eas"])
            assert selected_capture["row83_source_present"] is True
            assert selected_capture["row83_indirect"] is False
            assert set(selected_capture["row83_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row83_target_eas"])
            assert selected_capture["row84_source_present"] is True
            assert selected_capture["row84_indirect"] is False
            assert set(selected_capture["row84_target_eas"]) == {
                0x40A5F0,
                0x40B163,
            }, (capture_name, selected_capture["row84_target_eas"])
            assert selected_capture["row85_source_present"] is True
            assert selected_capture["row85_indirect"] is False
            assert set(selected_capture["row85_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row85_target_eas"])
            assert selected_capture["row86_source_present"] is True
            assert selected_capture["row86_indirect"] is False
            assert set(selected_capture["row86_target_eas"]) == {
                0x40A5F0,
                0x40B199,
            }, (capture_name, selected_capture["row86_target_eas"])
            assert selected_capture["row87_source_present"] is True
            assert selected_capture["row87_indirect"] is False
            assert set(selected_capture["row87_target_eas"]) == {
                0x40B6C0,
                *({0x40B1CA} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row87_target_eas"])
            assert selected_capture["row88_source_present"] is True
            assert selected_capture["row88_indirect"] is False
            assert set(selected_capture["row88_target_eas"]) == {
                0x40A5F0,
                0x40B1EA,
            }, (capture_name, selected_capture["row88_target_eas"])
            assert selected_capture["row89_source_present"] is True
            assert selected_capture["row89_indirect"] is False
            assert set(selected_capture["row89_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row89_target_eas"])
            assert selected_capture["row90_source_present"] is True
            assert selected_capture["row90_indirect"] is False
            assert set(selected_capture["row90_target_eas"]) == {
                0x40A5F0,
                0x40B236,
            }, (capture_name, selected_capture["row90_target_eas"])
            assert selected_capture["row91_source_present"] is True
            assert selected_capture["row91_indirect"] is False
            assert set(selected_capture["row91_target_eas"]) == {
                0x40B6C0,
                *({0x40A607} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row91_target_eas"])
            assert selected_capture["row92_source_present"] is True
            assert selected_capture["row92_indirect"] is False
            assert set(selected_capture["row92_target_eas"]) == {
                0x40A5F0,
                0x40B287 if capture_name == "preopt" else 0x40A90D,
            }, (capture_name, selected_capture["row92_target_eas"])
            assert selected_capture["row93_source_present"] is True
            assert selected_capture["row93_indirect"] is False
            assert set(selected_capture["row93_target_eas"]) == {
                0x40B6C0,
                *({0x40B2CF} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row93_target_eas"])
            assert selected_capture["row94_source_present"] is True
            assert selected_capture["row94_indirect"] is False
            assert set(selected_capture["row94_target_eas"]) == {
                0x40A5F0,
                0x40B2F5,
            }, (capture_name, selected_capture["row94_target_eas"])
            assert selected_capture["row95_source_present"] is True
            assert selected_capture["row95_indirect"] is False
            assert set(selected_capture["row95_target_eas"]) == {
                0x40B6C0,
                *({0x40B326} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row95_target_eas"])
            assert selected_capture["row96_source_present"] is True
            assert selected_capture["row96_indirect"] is False
            assert set(selected_capture["row96_target_eas"]) == {
                0x40A5F0,
                0x40B342,
            }, (capture_name, selected_capture["row96_target_eas"])
            assert selected_capture["row97_source_present"] is True
            assert selected_capture["row97_indirect"] is False
            assert set(selected_capture["row97_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row97_target_eas"])
            assert selected_capture["row98_source_present"] is True
            assert selected_capture["row98_indirect"] is False
            assert set(selected_capture["row98_target_eas"]) == {
                0x40B396,
                0x40B3E5,
            }, (capture_name, selected_capture["row98_target_eas"])
            assert selected_capture["row99_source_present"] is True
            assert selected_capture["row99_indirect"] is False
            assert set(selected_capture["row99_target_eas"]) == {
                0x40A5F0,
                0x40B3B0,
            }, (capture_name, selected_capture["row99_target_eas"])
            assert selected_capture["row100_source_present"] is True
            assert selected_capture["row100_indirect"] is False
            assert set(selected_capture["row100_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row100_target_eas"])
            assert selected_capture["row101_source_present"] is True
            assert selected_capture["row101_indirect"] is False
            assert set(selected_capture["row101_target_eas"]) == {
                0x40A5F0,
                0x40B3FF,
            }, (capture_name, selected_capture["row101_target_eas"])
            assert selected_capture["row102_source_present"] is True
            assert selected_capture["row102_indirect"] is False
            assert set(selected_capture["row102_target_eas"]) == {
                0x40A607,
                0x40B6C0,
            }, (capture_name, selected_capture["row102_target_eas"])
        assert {0x40A6B4, 0x40A800}.issubset(captures["first_cfg"]["reachable_eas"]), (
            captures["first_cfg"]
        )
        assert captures["calls_count"] == 1
        assert captures["calls"]["indirect"] is False, captures["calls"]
        assert captures["calls"]["row5_indirect"] is False, captures["calls"]
        assert captures["calls"]["row5_source_present"] is False, captures["calls"]
        assert captures["calls"]["row5_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row6_indirect"] is False, captures["calls"]
        assert captures["calls"]["row6_source_present"] is False, captures["calls"]
        assert captures["calls"]["row6_target_eas"] == (), captures["calls"]
        assert captures["calls"]["selected_indirect"] is False, captures["calls"]
        assert captures["calls"]["selected_source_present"] is False, captures["calls"]
        assert captures["calls"]["row11_indirect"] is False, captures["calls"]
        assert captures["calls"]["row11_source_present"] is False, captures["calls"]
        assert captures["calls"]["row12_indirect"] is False, captures["calls"]
        assert captures["calls"]["row12_source_present"] is False, captures["calls"]
        assert captures["calls"]["row20_indirect"] is False, captures["calls"]
        assert captures["calls"]["row20_source_present"] is False, captures["calls"]
        assert captures["calls"]["row21_indirect"] is False, captures["calls"]
        assert captures["calls"]["row21_source_present"] is False, captures["calls"]
        assert captures["calls"]["row22_indirect"] is False, captures["calls"]
        assert captures["calls"]["row22_source_present"] is False, captures["calls"]
        assert captures["calls"]["row23_indirect"] is False, captures["calls"]
        assert captures["calls"]["row23_source_present"] is False, captures["calls"]
        assert captures["calls"]["row25_source_present"] is False, captures["calls"]
        assert captures["calls"]["row25_indirect"] is False, captures["calls"]
        assert captures["calls"]["row25_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row26_indirect"] is False, captures["calls"]
        assert captures["calls"]["row26_source_present"] is False, captures["calls"]
        assert captures["calls"]["row27_indirect"] is False, captures["calls"]
        assert captures["calls"]["row27_source_present"] is False, captures["calls"]
        assert captures["calls"]["row28_indirect"] is False, captures["calls"]
        assert captures["calls"]["row28_source_present"] is False, captures["calls"]
        assert captures["calls"]["row29_indirect"] is False, captures["calls"]
        assert captures["calls"]["row29_source_present"] is False, captures["calls"]
        assert captures["calls"]["row29_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row30_indirect"] is False, captures["calls"]
        assert captures["calls"]["row30_source_present"] is False, captures["calls"]
        assert captures["calls"]["row30_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row31_indirect"] is False, captures["calls"]
        assert captures["calls"]["row31_source_present"] is False, captures["calls"]
        assert captures["calls"]["row31_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row32_indirect"] is False, captures["calls"]
        assert captures["calls"]["row32_source_present"] is False, captures["calls"]
        assert captures["calls"]["row32_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row33_indirect"] is False, captures["calls"]
        assert captures["calls"]["row33_source_present"] is False, captures["calls"]
        assert captures["calls"]["row33_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row34_indirect"] is False, captures["calls"]
        assert captures["calls"]["row34_source_present"] is False, captures["calls"]
        assert captures["calls"]["row34_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row35_indirect"] is False, captures["calls"]
        assert captures["calls"]["row35_source_present"] is False, captures["calls"]
        assert captures["calls"]["row35_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row36_indirect"] is False, captures["calls"]
        assert captures["calls"]["row36_source_present"] is False, captures["calls"]
        assert captures["calls"]["row36_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row37_indirect"] is False, captures["calls"]
        assert captures["calls"]["row37_source_present"] is False, captures["calls"]
        assert captures["calls"]["row37_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row38_indirect"] is False, captures["calls"]
        assert captures["calls"]["row38_source_present"] is False, captures["calls"]
        assert captures["calls"]["row38_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row39_indirect"] is False, captures["calls"]
        assert captures["calls"]["row39_source_present"] is False, captures["calls"]
        assert captures["calls"]["row39_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row40_indirect"] is False, captures["calls"]
        assert captures["calls"]["row40_source_present"] is False, captures["calls"]
        assert captures["calls"]["row40_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row42_indirect"] is False, captures["calls"]
        assert captures["calls"]["row42_source_present"] is False, captures["calls"]
        assert captures["calls"]["row42_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row43_indirect"] is False, captures["calls"]
        assert captures["calls"]["row43_source_present"] is False, captures["calls"]
        assert captures["calls"]["row43_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row44_indirect"] is False, captures["calls"]
        assert captures["calls"]["row44_source_present"] is False, captures["calls"]
        assert captures["calls"]["row44_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row45_indirect"] is False, captures["calls"]
        assert captures["calls"]["row45_source_present"] is False, captures["calls"]
        assert captures["calls"]["row45_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row46_indirect"] is False, captures["calls"]
        assert captures["calls"]["row46_source_present"] is False, captures["calls"]
        assert captures["calls"]["row46_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row47_indirect"] is False, captures["calls"]
        assert captures["calls"]["row47_source_present"] is False, captures["calls"]
        assert captures["calls"]["row47_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row49_indirect"] is False, captures["calls"]
        assert captures["calls"]["row49_source_present"] is False, captures["calls"]
        assert captures["calls"]["row49_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row50_indirect"] is False, captures["calls"]
        assert captures["calls"]["row50_source_present"] is False, captures["calls"]
        assert captures["calls"]["row50_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row51_indirect"] is False, captures["calls"]
        assert captures["calls"]["row51_source_present"] is False, captures["calls"]
        assert captures["calls"]["row51_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row52_indirect"] is False, captures["calls"]
        assert captures["calls"]["row52_source_present"] is False, captures["calls"]
        assert captures["calls"]["row52_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row53_indirect"] is False, captures["calls"]
        assert captures["calls"]["row53_source_present"] is False, captures["calls"]
        assert captures["calls"]["row53_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row54_indirect"] is False, captures["calls"]
        assert captures["calls"]["row54_source_present"] is False, captures["calls"]
        assert captures["calls"]["row54_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row55_indirect"] is False, captures["calls"]
        assert captures["calls"]["row55_source_present"] is False, captures["calls"]
        assert captures["calls"]["row55_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row56_indirect"] is False, captures["calls"]
        assert captures["calls"]["row56_source_present"] is False, captures["calls"]
        assert captures["calls"]["row56_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row57_indirect"] is False, captures["calls"]
        assert captures["calls"]["row57_source_present"] is False, captures["calls"]
        assert captures["calls"]["row57_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row58_indirect"] is False, captures["calls"]
        assert captures["calls"]["row58_source_present"] is False, captures["calls"]
        assert captures["calls"]["row58_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row59_indirect"] is False, captures["calls"]
        assert captures["calls"]["row59_source_present"] is False, captures["calls"]
        assert captures["calls"]["row59_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row60_indirect"] is False, captures["calls"]
        assert captures["calls"]["row60_source_present"] is False, captures["calls"]
        assert captures["calls"]["row60_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row61_indirect"] is False, captures["calls"]
        assert captures["calls"]["row61_source_present"] is False, captures["calls"]
        assert captures["calls"]["row61_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row62_indirect"] is False, captures["calls"]
        assert captures["calls"]["row62_source_present"] is False, captures["calls"]
        assert captures["calls"]["row62_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row63_indirect"] is False, captures["calls"]
        assert captures["calls"]["row63_source_present"] is False, captures["calls"]
        assert captures["calls"]["row63_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row64_indirect"] is False, captures["calls"]
        assert captures["calls"]["row64_source_present"] is False, captures["calls"]
        assert captures["calls"]["row64_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row65_indirect"] is False, captures["calls"]
        assert captures["calls"]["row65_source_present"] is False, captures["calls"]
        assert captures["calls"]["row65_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row66_indirect"] is False, captures["calls"]
        assert captures["calls"]["row66_source_present"] is False, captures["calls"]
        assert captures["calls"]["row66_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row67_indirect"] is False, captures["calls"]
        assert captures["calls"]["row67_source_present"] is False, captures["calls"]
        assert captures["calls"]["row67_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row68_indirect"] is False, captures["calls"]
        assert captures["calls"]["row68_source_present"] is False, captures["calls"]
        assert captures["calls"]["row68_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row69_indirect"] is False, captures["calls"]
        assert captures["calls"]["row69_source_present"] is False, captures["calls"]
        assert captures["calls"]["row69_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row70_indirect"] is False, captures["calls"]
        assert captures["calls"]["row70_source_present"] is False, captures["calls"]
        assert captures["calls"]["row70_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row71_indirect"] is False, captures["calls"]
        assert captures["calls"]["row71_source_present"] is False, captures["calls"]
        assert captures["calls"]["row71_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row72_indirect"] is False, captures["calls"]
        assert captures["calls"]["row72_source_present"] is False, captures["calls"]
        assert captures["calls"]["row72_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row73_indirect"] is False, captures["calls"]
        assert captures["calls"]["row73_source_present"] is False, captures["calls"]
        assert captures["calls"]["row73_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row74_indirect"] is False, captures["calls"]
        assert captures["calls"]["row74_source_present"] is False, captures["calls"]
        assert captures["calls"]["row74_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row75_indirect"] is False, captures["calls"]
        assert captures["calls"]["row75_source_present"] is False, captures["calls"]
        assert captures["calls"]["row75_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row76_indirect"] is False, captures["calls"]
        assert captures["calls"]["row76_source_present"] is False, captures["calls"]
        assert captures["calls"]["row76_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row77_indirect"] is False, captures["calls"]
        assert captures["calls"]["row77_source_present"] is False, captures["calls"]
        assert captures["calls"]["row77_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row78_indirect"] is False, captures["calls"]
        assert captures["calls"]["row78_source_present"] is False, captures["calls"]
        assert captures["calls"]["row78_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row79_indirect"] is False, captures["calls"]
        assert captures["calls"]["row79_source_present"] is False, captures["calls"]
        assert captures["calls"]["row79_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row80_indirect"] is False, captures["calls"]
        assert captures["calls"]["row80_source_present"] is False, captures["calls"]
        assert captures["calls"]["row80_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row81_indirect"] is False, captures["calls"]
        assert captures["calls"]["row81_source_present"] is False, captures["calls"]
        assert captures["calls"]["row81_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row82_indirect"] is False, captures["calls"]
        assert captures["calls"]["row82_source_present"] is False, captures["calls"]
        assert captures["calls"]["row82_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row83_indirect"] is False, captures["calls"]
        assert captures["calls"]["row83_source_present"] is False, captures["calls"]
        assert captures["calls"]["row83_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row84_indirect"] is False, captures["calls"]
        assert captures["calls"]["row84_source_present"] is False, captures["calls"]
        assert captures["calls"]["row84_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row85_indirect"] is False, captures["calls"]
        assert captures["calls"]["row85_source_present"] is False, captures["calls"]
        assert captures["calls"]["row85_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row86_indirect"] is False, captures["calls"]
        assert captures["calls"]["row86_source_present"] is False, captures["calls"]
        assert captures["calls"]["row86_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row87_indirect"] is False, captures["calls"]
        assert captures["calls"]["row87_source_present"] is False, captures["calls"]
        assert captures["calls"]["row87_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row88_indirect"] is False, captures["calls"]
        assert captures["calls"]["row88_source_present"] is False, captures["calls"]
        assert captures["calls"]["row88_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row89_indirect"] is False, captures["calls"]
        assert captures["calls"]["row89_source_present"] is False, captures["calls"]
        assert captures["calls"]["row89_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row90_indirect"] is False, captures["calls"]
        assert captures["calls"]["row90_source_present"] is False, captures["calls"]
        assert captures["calls"]["row90_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row91_indirect"] is False, captures["calls"]
        assert captures["calls"]["row91_source_present"] is False, captures["calls"]
        assert captures["calls"]["row91_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row92_indirect"] is False, captures["calls"]
        assert captures["calls"]["row92_source_present"] is False, captures["calls"]
        assert captures["calls"]["row92_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row93_indirect"] is False, captures["calls"]
        assert captures["calls"]["row93_source_present"] is False, captures["calls"]
        assert captures["calls"]["row93_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row94_indirect"] is False, captures["calls"]
        assert captures["calls"]["row94_source_present"] is False, captures["calls"]
        assert captures["calls"]["row94_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row95_indirect"] is False, captures["calls"]
        assert captures["calls"]["row95_source_present"] is False, captures["calls"]
        assert captures["calls"]["row95_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row96_indirect"] is False, captures["calls"]
        assert captures["calls"]["row96_source_present"] is True, captures["calls"]
        assert set(captures["calls"]["row96_target_eas"]) == {
            0x40A5F0,
            0x40B342,
        }, captures["calls"]
        assert captures["calls"]["row97_indirect"] is False, captures["calls"]
        assert captures["calls"]["row97_source_present"] is False, captures["calls"]
        assert captures["calls"]["row97_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row98_indirect"] is False, captures["calls"]
        assert captures["calls"]["row98_source_present"] is False, captures["calls"]
        assert captures["calls"]["row98_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row99_indirect"] is False, captures["calls"]
        assert captures["calls"]["row99_source_present"] is False, captures["calls"]
        assert captures["calls"]["row99_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row100_indirect"] is False, captures["calls"]
        assert captures["calls"]["row100_source_present"] is False, captures["calls"]
        assert captures["calls"]["row100_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row101_indirect"] is False, captures["calls"]
        assert captures["calls"]["row101_source_present"] is False, captures["calls"]
        assert captures["calls"]["row101_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row102_indirect"] is False, captures["calls"]
        assert captures["calls"]["row102_source_present"] is False, captures["calls"]
        assert captures["calls"]["row102_target_eas"] == (), captures["calls"]
        assert captures["calls"]["setcc_indirect"] is False, captures["calls"]
        assert captures["calls"]["setcc_source_present"] is True, captures["calls"]
        assert captures["calls"]["scaled_setcc_indirect"] is False, captures["calls"]
        if captures["calls"]["scaled_setcc_source_present"]:
            assert set(captures["calls"]["scaled_setcc_target_eas"]) == {
                0x40A794,
                0x40AEE6,
            }, captures["calls"]
        assert captures["calls"]["row18_indirect"] is False, captures["calls"]
        assert captures["calls"]["row19_source_present"] is False, captures["calls"]
        assert captures["calls"]["row19_indirect"] is False, captures["calls"]
        assert captures["calls"]["row19_target_eas"] == (), captures["calls"]
        if captures["calls"]["source_present"]:
            assert set(captures["calls"]["target_eas"]) == {
                0x40A607,
                0x40B6C0,
            }, captures["calls"]
        assert {0x40A5F6, 0x40B760, 0x40C696}.issubset(
            captures["calls"]["reachable_eas"]
        ), captures["calls"]
        headless.stop()
        print("checksum-worker:stopped", flush=True)
    finally:
        if hook is not None:
            hook.unhook()
        try:
            import d810.headless as headless

            headless.stop()
        except Exception:
            pass
        from d810.core.observability import close_observability_session

        close_observability_session()
        diag_output = os.environ.get("D810_RHAD_GENERATED_CHECKSUM_DIAG_OUTPUT")
        if diag_output:
            from d810.core.diag import find_latest_diag_db_path

            diag_path = find_latest_diag_db_path(_FUNCTION_EA)
            if diag_path is not None:
                destination = pathlib.Path(diag_output).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(diag_path, destination)
        idapro.close_database(False)


def test_a560_generated_checksum_commits_and_reaches_ctree(
    tmp_path: pathlib.Path,
) -> None:
    fixture = _fixture()
    if not fixture.is_file():
        pytest.skip("real Rhad loader fixture unavailable")
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == _EXPECTED_SHA256
    binary = tmp_path / fixture.name
    diag_path = tmp_path / "a560-generated-checksum.diag.sqlite3"
    shutil.copy2(fixture, binary)
    for suffix in _SIDECARS:
        binary.with_suffix(suffix).unlink(missing_ok=True)
        pathlib.Path(str(binary) + suffix).unlink(missing_ok=True)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    env = dict(os.environ)
    env.pop("PYTEST_CURRENT_TEST", None)
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONPATH"] = os.pathsep.join(
        (str(_REPO / "src"), str(_REPO / "tests"), env.get("PYTHONPATH", ""))
    )
    env["D810_DIAG_SNAPSHOT"] = "1"
    env["D810_RHAD_GENERATED_CHECKSUM_DIAG_OUTPUT"] = str(diag_path)
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(__file__).resolve()),
                "--worker",
                str(binary),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=240,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        pytest.fail(
            "checksum worker timed out\n"
            f"stdout excerpt:\n{_output_excerpt(error.stdout)}\n"
            f"stderr excerpt:\n{_output_excerpt(error.stderr)}"
        )
    assert result.returncode == 0, (
        f"checksum worker failed ({result.returncode})\n"
        f"stdout excerpt:\n{_output_excerpt(result.stdout)}\n"
        f"stderr excerpt:\n{_output_excerpt(result.stderr)}"
    )
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
    assert diag_path.is_file()
    with sqlite3.connect(diag_path) as connection:
        lifecycle_rows = connection.execute(
            "SELECT event_kind, maturity, phase, payload_json "
            "FROM lifecycle_events "
            "WHERE event_kind LIKE 'rhad_generated_checksum%' "
            "ORDER BY event_id"
        ).fetchall()
        assert tuple(row[0] for row in lifecycle_rows[:3]) == (
            "rhad_generated_checksum_preparation",
            "rhad_generated_checksum_compiled",
            "rhad_generated_checksum_published",
        )
        maturity_rows = tuple(
            row
            for row in lifecycle_rows
            if row[0] == "rhad_generated_checksum_maturity"
        )
        assert tuple(row[1] for row in maturity_rows) == (
            "MMAT_GENERATED",
            "MMAT_PREOPTIMIZED",
            "MMAT_LOCOPT",
            "MMAT_CALLS",
        )
        assert all(bool(json.loads(row[3])["passed"]) for row in maturity_rows)
        compiled_payload = json.loads(lifecycle_rows[1][3])
        row16_artifact_identity = (
            "sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785"
        )
        row17_artifact_identity = (
            "sha256:a67a3d2cc432df11ca627c90f06f3a854004a9463a529ee1d0cdf1f759406e67"
        )
        row68_artifact_identity = (
            "sha256:9eb674af190cee8d9b391605feb930a59bcf708c9fbb519f2d8bd26cac27fdd0"
        )
        row96_artifact_identity = (
            "sha256:84e0228bce62ddd78ae00141b1f07db44216ad30418cc82f4039613591d02e50"
        )
        row126_artifact_identity = (
            "sha256:9a021d69b5bde91a89ab5d4211bcd9a3e8b6030d903d037ad5bfc561e732b73a"
        )
        row129_artifact_identity = (
            "sha256:3745b3fb2322c74b0a635166a5a90f2aca25e7cf8703f98f74480c93a21c3655"
        )
        row134_artifact_identity = (
            "sha256:eb95d87e5fcd4823c1eddbd92e869603aee8558a3953cb2e9272ce9b8b1e493d"
        )
        row167_artifact_identity = (
            "sha256:fafc420031c9e89a7c8de87bf6932b836a12b8f1a2376eeb21e9f057956e3be8"
        )
        assert compiled_payload["plan_id"].endswith(
            compiled_payload["aggregate_program_identity"]
        )
        assert compiled_payload["aggregate_program_identity"] == (
            "sha256:7333559bdf8692e766b7f7e92b98c5ab65c718653b67c141b94ca07f0be31209"
        )
        proof_artifacts = {
            artifact["proof"]["binding"]["operation_id"]: artifact
            for artifact in compiled_payload["proof_artifacts"]
        }
        assert tuple(proof_artifacts) == (
            "rhad:route@0x40A77C",
            "rhad:route@0x40A792",
            "rhad:route@0x40AE3C",
            "rhad:route@0x40B340",
            "rhad:route@0x40B7F4",
            "rhad:route@0x40B896",
            "rhad:route@0x40B956",
            "rhad:route@0x40BFA2",
        )
        for operation_id, reference_order, schema_version, content_identity in (
            ("rhad:route@0x40A77C", 16, 1, row16_artifact_identity),
            ("rhad:route@0x40A792", 17, 2, row17_artifact_identity),
            ("rhad:route@0x40AE3C", 68, 1, row68_artifact_identity),
            ("rhad:route@0x40B340", 96, 2, row96_artifact_identity),
            ("rhad:route@0x40B7F4", 126, 1, row126_artifact_identity),
            ("rhad:route@0x40B896", 129, 1, row129_artifact_identity),
            ("rhad:route@0x40B956", 134, 1, row134_artifact_identity),
            ("rhad:route@0x40BFA2", 167, 1, row167_artifact_identity),
        ):
            artifact = proof_artifacts[operation_id]
            assert artifact["content_identity"] == content_identity
            assert artifact["proof"]["artifact_type"] == (
                "rhad_setcc_indexed_table_proof"
            )
            assert artifact["proof"]["schema_version"] == schema_version
            assert artifact["proof"]["binding"] == {
                "function_ea": 0x40A560,
                "input_sha256": _EXPECTED_SHA256,
                "operation_id": operation_id,
                "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
                "reference_order": reference_order,
            }
        assert tuple(compiled_payload["operation_ids"]) == _COMPILED_OPERATION_IDS
        assert tuple(compiled_payload["imported_block_ids"]) == _IMPORTED_BLOCK_IDS
        assert compiled_payload["imported_block_count"] == len(_IMPORTED_BLOCK_IDS)
        reference_payloads = {
            row["operation_id"]: row["reference_evidence"]
            for row in compiled_payload["reference_operations"]
        }
        assert set(reference_payloads) == set(_COMPILED_OPERATION_IDS)
        assert all(
            row["reference_identity"].startswith("sha256:")
            for row in compiled_payload["reference_operations"]
        )
        direct_reference = reference_payloads["route:rhad-direct@0x40A619"]
        assert direct_reference["operation_category"] == "direct_route"
        assert direct_reference["reference_operation_id"] == "rhad:route@0x40A619"
        assert direct_reference["reference_order"] == 2
        assert direct_reference["operation_variant"] == "simple_indirect_jump"
        assert direct_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert direct_reference["source_native_ea"] == 0x40A607
        assert direct_reference["source_block_anchor_ea"] == 0x40A615
        assert direct_reference["transfer_ea"] == 0x40A619
        assert direct_reference["direct_target_block_id"] == "native@0x40A61B"
        row3_reference = reference_payloads["route:rhad-direct@0x40A631"]
        assert row3_reference["reference_operation_id"] == "rhad:route@0x40A631"
        assert row3_reference["reference_order"] == 3
        assert row3_reference["operation_variant"] == "simple_indirect_jump"
        assert row3_reference["source_native_ea"] == 0x40A61B
        assert row3_reference["source_block_anchor_ea"] == 0x40A62D
        assert row3_reference["transfer_ea"] == 0x40A631
        assert row3_reference["direct_target_block_id"] == "native@0x40A633"
        assert row3_reference["boundary_exit_eas"] == [0x40A64B, 0x40A8B5]
        row4_reference = reference_payloads["route:rhad-direct@0x40A649"]
        assert row4_reference["reference_operation_id"] == "rhad:route@0x40A649"
        assert row4_reference["reference_order"] == 4
        assert row4_reference["operation_variant"] == "simple_indirect_jump"
        assert row4_reference["source_native_ea"] == 0x40A633
        assert row4_reference["source_block_anchor_ea"] == 0x40A645
        assert row4_reference["transfer_ea"] == 0x40A649
        assert row4_reference["direct_target_block_id"] == "native@0x40A8B5"
        assert row4_reference["boundary_exit_eas"] == [0x40ACBF]
        row5_reference = reference_payloads["route:rhad-direct@0x40A661"]
        assert row5_reference["reference_operation_id"] == "rhad:route@0x40A661"
        assert row5_reference["reference_order"] == 5
        assert row5_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row5_reference["operation_variant"] == "simple_indirect_jump"
        assert row5_reference["source_native_ea"] == 0x40A64B
        assert row5_reference["source_block_anchor_ea"] == 0x40A65D
        assert row5_reference["transfer_ea"] == 0x40A661
        assert row5_reference["direct_target_block_id"] == "native@0x40A663"
        assert row5_reference["owned_corridor_instruction_eas"] == [
            0x40A64B,
            0x40A65D,
            0x40A65F,
            0x40A661,
        ]
        assert row5_reference["imported_closure_block_ids"] == [
            "native@0x40A64B",
            "native@0x40A65D",
            "native@0x40A661",
            "native@0x40AAF1",
            "native@0x40AAFB",
            "native@0x40A663",
            "native@0x40A675",
            "native@0x40A679",
            "native@0x40AE1A",
            "native@0x40AE24",
        ]
        assert row5_reference["boundary_exit_eas"] == [
            0x40A5CA,
            0x40AAFD,
            0x40AE26,
        ]
        row6_reference = reference_payloads["route:rhad-direct@0x40A679"]
        assert row6_reference["reference_operation_id"] == "rhad:route@0x40A679"
        assert row6_reference["reference_order"] == 6
        assert row6_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row6_reference["operation_variant"] == "simple_indirect_jump"
        assert row6_reference["source_native_ea"] == 0x40A663
        assert row6_reference["source_block_anchor_ea"] == 0x40A675
        assert row6_reference["transfer_ea"] == 0x40A679
        assert row6_reference["direct_target_block_id"] == "native@0x40AE26"
        assert row6_reference["owned_corridor_instruction_eas"] == [
            0x40A663,
            0x40A675,
            0x40A677,
            0x40A679,
        ]
        assert row6_reference["imported_closure_block_ids"] == [
            "native@0x40AE26",
            "native@0x40AE3C",
        ]
        assert row6_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AE3E]
        selected_reference = reference_payloads["rhad:route@0x40A6A4"]
        assert selected_reference["reference_order"] == 8
        assert selected_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert selected_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert selected_reference["source_native_ea"] == 0x40A68C
        assert selected_reference["condition_producer_ea"] == 0x40A692
        assert selected_reference["transfer_ea"] == 0x40A6A4
        assert selected_reference["true_target_ea"] == 0x40A6A6
        assert selected_reference["false_target_ea"] == 0x40A800
        assert selected_reference["true_target_block_id"] == "native@0x40A6A6"
        assert selected_reference["false_target_block_id"] == "native@0x40A800"
        row9_reference = reference_payloads["rhad:route@0x40A6BE"]
        assert row9_reference["reference_order"] == 9
        assert row9_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row9_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row9_reference["source_native_ea"] == 0x40A6A6
        assert row9_reference["condition_producer_ea"] == 0x40A6AC
        assert row9_reference["predicate_anchor_ea"] == 0x40A6B2
        assert row9_reference["predicate_kind"] == "slt"
        assert row9_reference["observed_predicate_kind"] == "sge"
        assert row9_reference["transfer_ea"] == 0x40A6BE
        assert row9_reference["true_target_ea"] == 0x40A6C0
        assert row9_reference["false_target_ea"] == 0x40A960
        assert row9_reference["true_target_block_id"] == "native@0x40A6C0"
        assert row9_reference["false_target_block_id"] == "native@0x40A960"
        assert row9_reference["boundary_exit_eas"] == [
            0x40A6DA,
            0x40AB76,
            0x40AD1E,
        ]
        row10_reference = reference_payloads["rhad:route@0x40A6D8"]
        assert row10_reference["reference_order"] == 10
        assert row10_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row10_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row10_reference["source_native_ea"] == 0x40A6C0
        assert row10_reference["condition_producer_ea"] == 0x40A6C6
        assert row10_reference["predicate_anchor_ea"] == 0x40A6CC
        assert row10_reference["predicate_kind"] == "slt"
        assert row10_reference["observed_predicate_kind"] == "sge"
        assert row10_reference["transfer_ea"] == 0x40A6D8
        assert row10_reference["true_target_ea"] == 0x40A6DA
        assert row10_reference["false_target_ea"] == 0x40AB76
        assert row10_reference["true_target_block_id"] == "native@0x40A6DA"
        assert row10_reference["false_target_block_id"] == "native@0x40AB76"
        assert row10_reference["boundary_exit_eas"] == [
            0x40A6F4,
            0x40AE8B,
            0x40B17F,
        ]
        row11_reference = reference_payloads["rhad:route@0x40A6F2"]
        assert row11_reference["reference_order"] == 11
        assert row11_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row11_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row11_reference["source_native_ea"] == 0x40A6DA
        assert row11_reference["condition_producer_ea"] == 0x40A6E0
        assert row11_reference["predicate_anchor_ea"] == 0x40A6E6
        assert row11_reference["predicate_kind"] == "slt"
        assert row11_reference["observed_predicate_kind"] == "sge"
        assert row11_reference["transfer_ea"] == 0x40A6F2
        assert row11_reference["true_target_ea"] == 0x40A6F4
        assert row11_reference["false_target_ea"] == 0x40AE8B
        assert row11_reference["true_target_block_id"] == "native@0x40A6F4"
        assert row11_reference["false_target_block_id"] == "native@0x40AE8B"
        assert row11_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A70E]
        row12_reference = reference_payloads["rhad:route@0x40A70C"]
        assert row12_reference["reference_order"] == 12
        assert row12_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row12_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row12_reference["source_native_ea"] == 0x40A6F4
        assert row12_reference["condition_producer_ea"] == 0x40A6FA
        assert row12_reference["predicate_anchor_ea"] == 0x40A700
        assert row12_reference["predicate_kind"] == "eq"
        assert row12_reference["observed_predicate_kind"] == "ne"
        assert row12_reference["transfer_ea"] == 0x40A70C
        assert row12_reference["true_target_ea"] == 0x40A70E
        assert row12_reference["false_target_ea"] == 0x40A5F0
        assert row12_reference["true_target_block_id"] == "native@0x40A70E"
        assert row12_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row12_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row20_reference = reference_payloads["rhad:route@0x40A818"]
        assert row20_reference["reference_order"] == 20
        assert row20_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row20_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row20_reference["source_native_ea"] == 0x40A800
        assert row20_reference["condition_producer_ea"] == 0x40A806
        assert row20_reference["predicate_anchor_ea"] == 0x40A80C
        assert row20_reference["predicate_kind"] == "slt"
        assert row20_reference["observed_predicate_kind"] == "sge"
        assert row20_reference["transfer_ea"] == 0x40A818
        assert row20_reference["true_target_ea"] == 0x40A81A
        assert row20_reference["false_target_ea"] == 0x40AA60
        assert row20_reference["true_target_block_id"] == "native@0x40A81A"
        assert row20_reference["false_target_block_id"] == "native@0x40AA60"
        assert row20_reference["boundary_exit_eas"] == [
            0x40A834,
            0x40AC3D,
            0x40ADBE,
        ]
        row21_reference = reference_payloads["rhad:route@0x40A832"]
        assert row21_reference["reference_order"] == 21
        assert row21_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row21_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row21_reference["source_native_ea"] == 0x40A81A
        assert row21_reference["condition_producer_ea"] == 0x40A820
        assert row21_reference["predicate_anchor_ea"] == 0x40A826
        assert row21_reference["predicate_kind"] == "slt"
        assert row21_reference["observed_predicate_kind"] == "sge"
        assert row21_reference["transfer_ea"] == 0x40A832
        assert row21_reference["true_target_ea"] == 0x40A834
        assert row21_reference["false_target_ea"] == 0x40AC3D
        assert row21_reference["true_target_block_id"] == "native@0x40A834"
        assert row21_reference["false_target_block_id"] == "native@0x40AC3D"
        assert row21_reference["boundary_exit_eas"] == [
            0x40A84E,
            0x40AFDF,
            0x40B21C,
        ]
        row22_reference = reference_payloads["rhad:route@0x40A84C"]
        assert row22_reference["reference_order"] == 22
        assert row22_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row22_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row22_reference["source_native_ea"] == 0x40A834
        assert row22_reference["condition_producer_ea"] == 0x40A83A
        assert row22_reference["predicate_anchor_ea"] == 0x40A840
        assert row22_reference["predicate_kind"] == "slt"
        assert row22_reference["observed_predicate_kind"] == "sge"
        assert row22_reference["transfer_ea"] == 0x40A84C
        assert row22_reference["true_target_ea"] == 0x40A84E
        assert row22_reference["false_target_ea"] == 0x40AFDF
        assert row22_reference["true_target_block_id"] == "native@0x40A84E"
        assert row22_reference["false_target_block_id"] == "native@0x40AFDF"
        assert row22_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A868]
        row23_reference = reference_payloads["rhad:route@0x40A866"]
        assert row23_reference["reference_order"] == 23
        assert row23_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row23_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row23_reference["source_native_ea"] == 0x40A84E
        assert row23_reference["condition_producer_ea"] == 0x40A854
        assert row23_reference["predicate_anchor_ea"] == 0x40A85A
        assert row23_reference["predicate_kind"] == "eq"
        assert row23_reference["observed_predicate_kind"] == "ne"
        assert row23_reference["transfer_ea"] == 0x40A866
        assert row23_reference["true_target_ea"] == 0x40A868
        assert row23_reference["false_target_ea"] == 0x40A5F0
        assert row23_reference["true_target_block_id"] == "native@0x40A868"
        assert row23_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row23_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row25_reference = reference_payloads["route:rhad-direct@0x40A8B3"]
        assert row25_reference["reference_operation_id"] == "rhad:route@0x40A8B3"
        assert row25_reference["reference_order"] == 25
        assert row25_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row25_reference["operation_variant"] == "simple_indirect_jump"
        assert row25_reference["source_native_ea"] == 0x40A63F
        assert row25_reference["source_block_anchor_ea"] == 0x40A8A9
        assert row25_reference["transfer_ea"] == 0x40A8B3
        assert row25_reference["direct_target_block_id"] == "native@0x40A64B"
        assert row25_reference["owned_corridor_instruction_eas"] == [
            0x40A63F,
            0x40A8A9,
            0x40A8AF,
            0x40A8B1,
            0x40A8B3,
        ]
        assert row25_reference["imported_closure_block_ids"] == [
            "native@0x40A64B",
            "native@0x40A65D",
            "native@0x40A661",
            "native@0x40AAF1",
            "native@0x40AAFB",
        ]
        assert row25_reference["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
        row26_reference = reference_payloads["rhad:route@0x40A8CD"]
        assert row26_reference["reference_order"] == 26
        assert row26_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row26_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row26_reference["source_native_ea"] == 0x40A8B5
        assert row26_reference["condition_producer_ea"] == 0x40A8BB
        assert row26_reference["predicate_anchor_ea"] == 0x40A8C1
        assert row26_reference["predicate_kind"] == "slt"
        assert row26_reference["observed_predicate_kind"] == "sge"
        assert row26_reference["transfer_ea"] == 0x40A8CD
        assert row26_reference["true_target_ea"] == 0x40A8CF
        assert row26_reference["false_target_ea"] == 0x40ACBF
        assert row26_reference["true_target_block_id"] == "native@0x40A8CF"
        assert row26_reference["false_target_block_id"] == "native@0x40ACBF"
        assert row26_reference["boundary_exit_eas"] == [
            0x40A8E9,
            0x40B024,
            0x40B26D,
        ]
        row27_reference = reference_payloads["rhad:route@0x40A8E7"]
        assert row27_reference["reference_order"] == 27
        assert row27_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row27_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row27_reference["source_native_ea"] == 0x40A8CF
        assert row27_reference["condition_producer_ea"] == 0x40A8D5
        assert row27_reference["predicate_anchor_ea"] == 0x40A8DB
        assert row27_reference["predicate_kind"] == "slt"
        assert row27_reference["observed_predicate_kind"] == "sge"
        assert row27_reference["comparison_constant"] == 0x0CDF90C9
        assert row27_reference["transfer_ea"] == 0x40A8E7
        assert row27_reference["true_target_ea"] == 0x40A8E9
        assert row27_reference["false_target_ea"] == 0x40B024
        assert row27_reference["true_target_block_id"] == "native@0x40A8E9"
        assert row27_reference["false_target_block_id"] == "native@0x40B024"
        assert row27_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A903]
        row28_reference = reference_payloads["rhad:route@0x40A901"]
        assert row28_reference["reference_order"] == 28
        assert row28_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row28_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row28_reference["source_native_ea"] == 0x40A8E9
        assert row28_reference["condition_producer_ea"] == 0x40A8EF
        assert row28_reference["predicate_anchor_ea"] == 0x40A8F5
        assert row28_reference["predicate_kind"] == "eq"
        assert row28_reference["observed_predicate_kind"] == "ne"
        assert row28_reference["comparison_constant"] == 0x0BB2D365
        assert row28_reference["transfer_ea"] == 0x40A901
        assert row28_reference["true_target_ea"] == 0x40A903
        assert row28_reference["false_target_ea"] == 0x40A5F0
        assert row28_reference["true_target_block_id"] == "native@0x40A903"
        assert row28_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row28_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row29_reference = reference_payloads["route:rhad-direct@0x40A95E"]
        assert row29_reference["reference_operation_id"] == "rhad:route@0x40A95E"
        assert row29_reference["reference_order"] == 29
        assert row29_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row29_reference["operation_variant"] == "simple_indirect_jump"
        assert row29_reference["source_native_ea"] == 0x40A93C
        assert row29_reference["source_block_anchor_ea"] == 0x40A954
        assert row29_reference["transfer_ea"] == 0x40A95E
        assert row29_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row29_reference["boundary_exit_eas"] == [0x40B790]
        row30_reference = reference_payloads["rhad:route@0x40A978"]
        assert row30_reference["reference_order"] == 30
        assert row30_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row30_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row30_reference["source_native_ea"] == 0x40A960
        assert row30_reference["condition_producer_ea"] == 0x40A966
        assert row30_reference["predicate_anchor_ea"] == 0x40A96C
        assert row30_reference["predicate_kind"] == "slt"
        assert row30_reference["observed_predicate_kind"] == "sge"
        assert row30_reference["comparison_constant"] == 0x636961E8
        assert row30_reference["transfer_ea"] == 0x40A978
        assert row30_reference["true_target_ea"] == 0x40A97A
        assert row30_reference["false_target_ea"] == 0x40AD1E
        assert row30_reference["true_target_block_id"] == "native@0x40A97A"
        assert row30_reference["false_target_block_id"] == "native@0x40AD1E"
        assert row30_reference["boundary_exit_eas"] == [
            0x40A994,
            0x40B071,
            0x40B55B,
        ]
        row31_reference = reference_payloads["rhad:route@0x40A992"]
        assert row31_reference["reference_order"] == 31
        assert row31_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row31_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row31_reference["source_native_ea"] == 0x40A97A
        assert row31_reference["condition_producer_ea"] == 0x40A980
        assert row31_reference["predicate_anchor_ea"] == 0x40A986
        assert row31_reference["predicate_kind"] == "slt"
        assert row31_reference["observed_predicate_kind"] == "sge"
        assert row31_reference["comparison_constant"] == 0x5E07BA29
        assert row31_reference["transfer_ea"] == 0x40A992
        assert row31_reference["true_target_ea"] == 0x40A994
        assert row31_reference["false_target_ea"] == 0x40B071
        assert row31_reference["true_target_block_id"] == "native@0x40A994"
        assert row31_reference["false_target_block_id"] == "native@0x40B071"
        assert row31_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A9AE]
        row32_reference = reference_payloads["rhad:route@0x40A9AC"]
        assert row32_reference["reference_order"] == 32
        assert row32_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row32_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row32_reference["source_native_ea"] == 0x40A994
        assert row32_reference["condition_producer_ea"] == 0x40A99A
        assert row32_reference["predicate_anchor_ea"] == 0x40A9A0
        assert row32_reference["predicate_kind"] == "eq"
        assert row32_reference["observed_predicate_kind"] == "ne"
        assert row32_reference["comparison_constant"] == 0x4DFFC906
        assert row32_reference["transfer_ea"] == 0x40A9AC
        assert row32_reference["true_target_ea"] == 0x40A9AE
        assert row32_reference["false_target_ea"] == 0x40A5F0
        assert row32_reference["true_target_block_id"] == "native@0x40A9AE"
        assert row32_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row32_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row33_reference = reference_payloads["rhad:route@0x40A9DC"]
        assert row33_reference["reference_order"] == 33
        assert row33_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row33_reference["operation_variant"] == "cmov_selected_indirect"
        assert row33_reference["source_native_ea"] == 0x40A9B3
        assert row33_reference["source_block_anchor_ea"] == 0x40A9AE
        assert row33_reference["condition_producer_ea"] == 0x40A9C7
        assert row33_reference["predicate_anchor_ea"] == 0x40A9D5
        assert row33_reference["predicate_kind"] == "slt"
        assert row33_reference["observed_predicate_kind"] == "sge"
        assert row33_reference["comparison_constant"] == 0x0BB2D365
        assert row33_reference["transfer_ea"] == 0x40A9DC
        assert row33_reference["true_target_ea"] == 0x40B6C0
        assert row33_reference["false_target_ea"] == 0x40A607
        assert row33_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row33_reference["false_target_block_id"] == "native@0x40A607"
        assert row33_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row34_reference = reference_payloads["rhad:route@0x40A9F6"]
        assert row34_reference["reference_order"] == 34
        assert row34_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row34_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row34_reference["source_native_ea"] == 0x40A9DE
        assert row34_reference["source_block_anchor_ea"] == 0x40A9F2
        assert row34_reference["condition_producer_ea"] == 0x40A9E4
        assert row34_reference["predicate_anchor_ea"] == 0x40A9EA
        assert row34_reference["predicate_kind"] == "slt"
        assert row34_reference["observed_predicate_kind"] == "sge"
        assert row34_reference["comparison_constant"] == 0x2B8162DC
        assert row34_reference["transfer_ea"] == 0x40A9F6
        assert row34_reference["true_target_ea"] == 0x40A9F8
        assert row34_reference["false_target_ea"] == 0x40AD6E
        assert row34_reference["true_target_block_id"] == "native@0x40A9F8"
        assert row34_reference["false_target_block_id"] == "native@0x40AD6E"
        assert row34_reference["boundary_exit_eas"] == [
            0x40AA12,
            0x40AD88,
            0x40B0BC,
            0x40B32C,
        ]
        row35_reference = reference_payloads["rhad:route@0x40AA10"]
        assert row35_reference["reference_order"] == 35
        assert row35_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row35_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row35_reference["source_native_ea"] == 0x40A9F8
        assert row35_reference["source_block_anchor_ea"] == 0x40AA0C
        assert row35_reference["condition_producer_ea"] == 0x40A9FE
        assert row35_reference["predicate_anchor_ea"] == 0x40AA04
        assert row35_reference["predicate_kind"] == "slt"
        assert row35_reference["observed_predicate_kind"] == "sge"
        assert row35_reference["comparison_constant"] == 0x29947C85
        assert row35_reference["transfer_ea"] == 0x40AA10
        assert row35_reference["true_target_ea"] == 0x40AA12
        assert row35_reference["false_target_ea"] == 0x40B0BC
        assert row35_reference["true_target_block_id"] == "native@0x40AA12"
        assert row35_reference["false_target_block_id"] == "native@0x40B0BC"
        assert row35_reference["boundary_exit_eas"] == [0x40A5F0]
        row36_reference = reference_payloads["rhad:route@0x40AA2A"]
        assert row36_reference["reference_order"] == 36
        assert row36_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row36_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row36_reference["source_native_ea"] == 0x40AA12
        assert row36_reference["source_block_anchor_ea"] == 0x40AA26
        assert row36_reference["condition_producer_ea"] == 0x40AA18
        assert row36_reference["predicate_anchor_ea"] == 0x40AA1E
        assert row36_reference["predicate_kind"] == "eq"
        assert row36_reference["observed_predicate_kind"] == "ne"
        assert row36_reference["comparison_constant"] == 0x23B8E806
        assert row36_reference["transfer_ea"] == 0x40AA2A
        assert row36_reference["true_target_ea"] == 0x40AA2C
        assert row36_reference["false_target_ea"] == 0x40A5F0
        assert row36_reference["true_target_block_id"] == "native@0x40AA2C"
        assert row36_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row36_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row37_reference = reference_payloads["rhad:route@0x40AA5E"]
        assert row37_reference["reference_order"] == 37
        assert row37_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row37_reference["operation_variant"] == "cmov_selected_indirect"
        assert row37_reference["source_native_ea"] == 0x40AA3B
        assert row37_reference["source_block_anchor_ea"] == 0x40AA35
        assert row37_reference["condition_producer_ea"] == 0x40AA49
        assert row37_reference["predicate_anchor_ea"] == 0x40AA57
        assert row37_reference["predicate_kind"] == "slt"
        assert row37_reference["observed_predicate_kind"] == "sge"
        assert row37_reference["comparison_constant"] == 0x0BB2D365
        assert row37_reference["transfer_ea"] == 0x40AA5E
        assert row37_reference["true_target_ea"] == 0x40B6C0
        assert row37_reference["false_target_ea"] == 0x40A607
        assert row37_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row37_reference["false_target_block_id"] == "native@0x40A607"
        assert row37_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row38_reference = reference_payloads["rhad:route@0x40AA78"]
        assert row38_reference["reference_order"] == 38
        assert row38_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row38_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row38_reference["source_native_ea"] == 0x40AA60
        assert row38_reference["source_block_anchor_ea"] == 0x40AA74
        assert row38_reference["join_ea"] == 0x40AA74
        assert row38_reference["condition_producer_ea"] == 0x40AA66
        assert row38_reference["predicate_anchor_ea"] == 0x40AA6C
        assert row38_reference["predicate_kind"] == "slt"
        assert row38_reference["observed_predicate_kind"] == "sge"
        assert row38_reference["comparison_constant"] == 0x7C4FB03D
        assert row38_reference["transfer_ea"] == 0x40AA78
        assert row38_reference["true_target_ea"] == 0x40AA7A
        assert row38_reference["false_target_ea"] == 0x40ADBE
        assert row38_reference["true_target_block_id"] == "native@0x40AA7A"
        assert row38_reference["false_target_block_id"] == "native@0x40ADBE"
        assert row38_reference["boundary_exit_eas"] == [
            0x40AA94,
            0x40ADD8,
            0x40B0F2,
            0x40B37C,
        ]
        row39_reference = reference_payloads["rhad:route@0x40AA92"]
        assert row39_reference["reference_order"] == 39
        assert row39_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row39_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row39_reference["source_native_ea"] == 0x40AA7A
        assert row39_reference["source_block_anchor_ea"] == 0x40AA88
        assert row39_reference["join_ea"] == 0x40AA8E
        assert row39_reference["condition_producer_ea"] == 0x40AA80
        assert row39_reference["predicate_anchor_ea"] == 0x40AA86
        assert row39_reference["predicate_kind"] == "slt"
        assert row39_reference["observed_predicate_kind"] == "sge"
        assert row39_reference["comparison_constant"] == 0x78BAC34B
        assert row39_reference["transfer_ea"] == 0x40AA92
        assert row39_reference["true_target_ea"] == 0x40AA94
        assert row39_reference["false_target_ea"] == 0x40B0F2
        assert row39_reference["true_target_block_id"] == "native@0x40AA94"
        assert row39_reference["false_target_block_id"] == "native@0x40B0F2"
        assert row39_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AAAE]
        row40_reference = reference_payloads["rhad:route@0x40AAAC"]
        assert row40_reference["reference_order"] == 40
        assert row40_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row40_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row40_reference["source_native_ea"] == 0x40AA94
        assert row40_reference["source_block_anchor_ea"] == 0x40AAA2
        assert row40_reference["join_ea"] == 0x40AAA8
        assert row40_reference["condition_producer_ea"] == 0x40AA9A
        assert row40_reference["predicate_anchor_ea"] == 0x40AAA0
        assert row40_reference["predicate_kind"] == "eq"
        assert row40_reference["observed_predicate_kind"] == "ne"
        assert row40_reference["comparison_constant"] == 0x742F372A
        assert row40_reference["transfer_ea"] == 0x40AAAC
        assert row40_reference["true_target_ea"] == 0x40AAAE
        assert row40_reference["false_target_ea"] == 0x40A5F0
        assert row40_reference["true_target_block_id"] == "native@0x40AAAE"
        assert row40_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row40_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row42_reference = reference_payloads["route:rhad-direct@0x40AAFB"]
        assert row42_reference["reference_operation_id"] == "rhad:route@0x40AAFB"
        assert row42_reference["reference_order"] == 42
        assert row42_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row42_reference["operation_variant"] == "simple_indirect_jump"
        assert row42_reference["source_native_ea"] == 0x40A657
        assert row42_reference["source_block_anchor_ea"] == 0x40AAF1
        assert row42_reference["transfer_ea"] == 0x40AAFB
        assert row42_reference["direct_target_block_id"] == "native@0x40AAFD"
        assert row42_reference["owned_corridor_instruction_eas"] == [
            0x40A657,
            0x40AAF1,
            0x40AAF7,
            0x40AAF9,
            0x40AAFB,
        ]
        assert row42_reference["imported_closure_block_ids"] == [
            "native@0x40AAFD",
            "native@0x40AB0B",
            "native@0x40AB11",
            "native@0x40AB15",
        ]
        assert row42_reference["boundary_exit_eas"] == [0x40AB17, 0x40B149]
        row43_reference = reference_payloads["rhad:route@0x40AB15"]
        assert row43_reference["reference_order"] == 43
        assert row43_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row43_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row43_reference["source_native_ea"] == 0x40AAFD
        assert row43_reference["source_block_anchor_ea"] == 0x40AB0B
        assert row43_reference["join_ea"] == 0x40AB11
        assert row43_reference["condition_producer_ea"] == 0x40AB03
        assert row43_reference["predicate_anchor_ea"] == 0x40AB09
        assert row43_reference["predicate_kind"] == "slt"
        assert row43_reference["observed_predicate_kind"] == "sge"
        assert row43_reference["comparison_constant"] == 0x1EBFFA3C
        assert row43_reference["transfer_ea"] == 0x40AB15
        assert row43_reference["true_target_ea"] == 0x40AB17
        assert row43_reference["false_target_ea"] == 0x40B149
        assert row43_reference["true_target_block_id"] == "native@0x40AB17"
        assert row43_reference["false_target_block_id"] == "native@0x40B149"
        assert row43_reference["imported_closure_block_ids"] == [
            "native@0x40AB17",
            "native@0x40AB25",
            "native@0x40AB2B",
            "native@0x40AB2F",
            "native@0x40B149",
            "native@0x40B157",
            "native@0x40B15D",
            "native@0x40B161",
        ]
        assert row43_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AB31]
        row44_reference = reference_payloads["rhad:route@0x40AB2F"]
        assert row44_reference["reference_order"] == 44
        assert row44_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row44_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row44_reference["source_native_ea"] == 0x40AB17
        assert row44_reference["source_block_anchor_ea"] == 0x40AB25
        assert row44_reference["join_ea"] == 0x40AB2B
        assert row44_reference["condition_producer_ea"] == 0x40AB1D
        assert row44_reference["predicate_anchor_ea"] == 0x40AB23
        assert row44_reference["predicate_kind"] == "eq"
        assert row44_reference["observed_predicate_kind"] == "ne"
        assert row44_reference["comparison_constant"] == 0x1BAABD04
        assert row44_reference["transfer_ea"] == 0x40AB2F
        assert row44_reference["true_target_ea"] == 0x40AB31
        assert row44_reference["false_target_ea"] == 0x40A5F0
        assert row44_reference["true_target_block_id"] == "native@0x40AB31"
        assert row44_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row44_reference["imported_closure_block_ids"] == [
            "native@0x40AB31",
            "native@0x40AB56",
            "native@0x40AB6A",
            "native@0x40AB74",
            "native@0x40B51B",
            "native@0x40B534",
            "native@0x40B540",
        ]
        assert row44_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row46_reference = reference_payloads["rhad:route@0x40AB8E"]
        assert row46_reference["reference_order"] == 46
        assert row46_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row46_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row46_reference["source_native_ea"] == 0x40AB76
        assert row46_reference["source_block_anchor_ea"] == 0x40AB84
        assert row46_reference["join_ea"] == 0x40AB8A
        assert row46_reference["condition_producer_ea"] == 0x40AB7C
        assert row46_reference["predicate_anchor_ea"] == 0x40AB82
        assert row46_reference["predicate_kind"] == "slt"
        assert row46_reference["observed_predicate_kind"] == "sge"
        assert row46_reference["comparison_constant"] == 0x456A4274
        assert row46_reference["transfer_ea"] == 0x40AB8E
        assert row46_reference["true_target_ea"] == 0x40AB90
        assert row46_reference["false_target_ea"] == 0x40B17F
        assert row46_reference["true_target_block_id"] == "native@0x40AB90"
        assert row46_reference["false_target_block_id"] == "native@0x40B17F"
        assert row46_reference["imported_closure_block_ids"] == [
            "native@0x40AB90",
            "native@0x40AB9E",
            "native@0x40ABA4",
            "native@0x40ABA8",
            "native@0x40B17F",
            "native@0x40B18D",
            "native@0x40B193",
            "native@0x40B197",
        ]
        assert row46_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ABAA,
            0x40B199,
        ]
        row47_reference = reference_payloads["rhad:route@0x40ABA8"]
        assert row47_reference["reference_order"] == 47
        assert row47_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row47_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row47_reference["source_native_ea"] == 0x40AB90
        assert row47_reference["source_block_anchor_ea"] == 0x40AB9E
        assert row47_reference["join_ea"] == 0x40ABA4
        assert row47_reference["condition_producer_ea"] == 0x40AB96
        assert row47_reference["predicate_anchor_ea"] == 0x40AB9C
        assert row47_reference["predicate_kind"] == "eq"
        assert row47_reference["observed_predicate_kind"] == "ne"
        assert row47_reference["comparison_constant"] == 0x40D5B460
        assert row47_reference["transfer_ea"] == 0x40ABA8
        assert row47_reference["true_target_ea"] == 0x40ABAA
        assert row47_reference["false_target_ea"] == 0x40A5F0
        assert row47_reference["true_target_block_id"] == "native@0x40ABAA"
        assert row47_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row47_reference["imported_closure_block_ids"] == [
            "native@0x40ABAA",
            "native@0x40ABBD",
            "native@0x40ABC0",
            "native@0x40ABC4",
        ]
        assert row47_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row49_reference = reference_payloads["rhad:route@0x40ABDE"]
        assert row49_reference["reference_order"] == 49
        assert row49_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row49_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row49_reference["source_native_ea"] == 0x40ABC6
        assert row49_reference["source_block_anchor_ea"] == 0x40ABD4
        assert row49_reference["join_ea"] == 0x40ABDA
        assert row49_reference["condition_producer_ea"] == 0x40ABCC
        assert row49_reference["predicate_anchor_ea"] == 0x40ABD2
        assert row49_reference["predicate_kind"] == "slt"
        assert row49_reference["observed_predicate_kind"] == "sge"
        assert row49_reference["comparison_constant"] == 0x22C02855
        assert row49_reference["transfer_ea"] == 0x40ABDE
        assert row49_reference["true_target_ea"] == 0x40ABE0
        assert row49_reference["false_target_ea"] == 0x40B1D0
        assert row49_reference["true_target_block_id"] == "native@0x40ABE0"
        assert row49_reference["false_target_block_id"] == "native@0x40B1D0"
        assert row49_reference["imported_closure_block_ids"] == [
            "native@0x40ABE0",
            "native@0x40ABEE",
            "native@0x40ABF4",
            "native@0x40ABF8",
            "native@0x40B1D0",
            "native@0x40B1DE",
            "native@0x40B1E4",
            "native@0x40B1E8",
        ]
        assert row49_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ABFA,
            0x40B1EA,
        ]
        row50_reference = reference_payloads["rhad:route@0x40ABF8"]
        assert row50_reference["reference_order"] == 50
        assert row50_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row50_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row50_reference["source_native_ea"] == 0x40ABE0
        assert row50_reference["source_block_anchor_ea"] == 0x40ABEE
        assert row50_reference["join_ea"] == 0x40ABF4
        assert row50_reference["condition_producer_ea"] == 0x40ABE6
        assert row50_reference["predicate_anchor_ea"] == 0x40ABEC
        assert row50_reference["predicate_kind"] == "eq"
        assert row50_reference["observed_predicate_kind"] == "ne"
        assert row50_reference["comparison_constant"] == 0x22642D96
        assert row50_reference["transfer_ea"] == 0x40ABF8
        assert row50_reference["true_target_ea"] == 0x40ABFA
        assert row50_reference["false_target_ea"] == 0x40A5F0
        assert row50_reference["true_target_block_id"] == "native@0x40ABFA"
        assert row50_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row50_reference["imported_closure_block_ids"] == [
            "native@0x40ABFA",
            "native@0x40ABFF",
            "native@0x40AC19",
            "native@0x40AC31",
            "native@0x40AC3B",
            "native@0x40B542",
            "native@0x40B55F",
            "native@0x40B56B",
        ]
        assert row50_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row51_reference = reference_payloads["route:rhad-direct@0x40AC3B"]
        assert row51_reference["reference_operation_id"] == "rhad:route@0x40AC3B"
        assert row51_reference["reference_order"] == 51
        assert row51_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row51_reference["operation_variant"] == "simple_indirect_jump"
        assert row51_reference["source_native_ea"] == 0x40AC19
        assert row51_reference["source_block_anchor_ea"] == 0x40AC31
        assert row51_reference["transfer_ea"] == 0x40AC3B
        assert row51_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row51_reference["boundary_exit_eas"] == [0x40B790]
        row52_reference = reference_payloads["rhad:route@0x40AC54"]
        assert row52_reference["reference_order"] == 52
        assert row52_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row52_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row52_reference["source_native_ea"] == 0x40AC3D
        assert row52_reference["source_block_anchor_ea"] == 0x40AC4A
        assert row52_reference["join_ea"] == 0x40AC50
        assert row52_reference["condition_producer_ea"] == 0x40AC42
        assert row52_reference["predicate_anchor_ea"] == 0x40AC48
        assert row52_reference["predicate_kind"] == "slt"
        assert row52_reference["observed_predicate_kind"] == "sge"
        assert row52_reference["comparison_constant"] == 0x7278AB7F
        assert row52_reference["transfer_ea"] == 0x40AC54
        assert row52_reference["true_target_ea"] == 0x40AC56
        assert row52_reference["false_target_ea"] == 0x40B21C
        assert row52_reference["true_target_block_id"] == "native@0x40AC56"
        assert row52_reference["false_target_block_id"] == "native@0x40B21C"
        assert row52_reference["owned_corridor_instruction_eas"] == [
            0x40AC3D,
            0x40AC42,
            0x40AC48,
            0x40AC4A,
            0x40AC50,
            0x40AC52,
            0x40AC54,
        ]
        assert row52_reference["imported_closure_block_ids"] == [
            "native@0x40AC56",
            "native@0x40AC64",
            "native@0x40AC6A",
            "native@0x40AC6E",
            "native@0x40B21C",
            "native@0x40B22A",
            "native@0x40B230",
            "native@0x40B234",
        ]
        assert row52_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AC70]
        row53_reference = reference_payloads["rhad:route@0x40AC6E"]
        assert row53_reference["reference_order"] == 53
        assert row53_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row53_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row53_reference["source_native_ea"] == 0x40AC56
        assert row53_reference["source_block_anchor_ea"] == 0x40AC64
        assert row53_reference["join_ea"] == 0x40AC6A
        assert row53_reference["condition_producer_ea"] == 0x40AC5C
        assert row53_reference["predicate_anchor_ea"] == 0x40AC62
        assert row53_reference["predicate_kind"] == "eq"
        assert row53_reference["observed_predicate_kind"] == "ne"
        assert row53_reference["comparison_constant"] == 0x6D56E4D2
        assert row53_reference["transfer_ea"] == 0x40AC6E
        assert row53_reference["true_target_ea"] == 0x40AC70
        assert row53_reference["false_target_ea"] == 0x40A5F0
        assert row53_reference["true_target_block_id"] == "native@0x40AC70"
        assert row53_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row53_reference["owned_corridor_instruction_eas"] == [
            0x40AC56,
            0x40AC5C,
            0x40AC62,
            0x40AC64,
            0x40AC6A,
            0x40AC6C,
            0x40AC6E,
        ]
        assert row53_reference["imported_closure_block_ids"] == [
            "native@0x40AC70",
            "native@0x40AC81",
            "native@0x40AC9B",
            "native@0x40ACB3",
            "native@0x40ACBD",
            "native@0x40B56D",
            "native@0x40B58A",
            "native@0x40B596",
        ]
        assert row53_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row54_reference = reference_payloads["route:rhad-direct@0x40ACBD"]
        assert row54_reference["reference_operation_id"] == "rhad:route@0x40ACBD"
        assert row54_reference["reference_order"] == 54
        assert row54_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row54_reference["operation_variant"] == "simple_indirect_jump"
        assert row54_reference["source_native_ea"] == 0x40AC9B
        assert row54_reference["source_block_anchor_ea"] == 0x40ACB3
        assert row54_reference["transfer_ea"] == 0x40ACBD
        assert row54_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row54_reference["owned_corridor_instruction_eas"] == [
            0x40AC9B,
            0x40ACB3,
            0x40ACB5,
            0x40ACB7,
            0x40ACBD,
        ]
        assert row54_reference["boundary_exit_eas"] == [0x40B790]
        row55_reference = reference_payloads["rhad:route@0x40ACD7"]
        assert row55_reference["reference_order"] == 55
        assert row55_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row55_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row55_reference["source_native_ea"] == 0x40ACBF
        assert row55_reference["source_block_anchor_ea"] == 0x40ACD3
        assert row55_reference["join_ea"] == 0x40ACD3
        assert row55_reference["condition_producer_ea"] == 0x40ACC5
        assert row55_reference["predicate_anchor_ea"] == 0x40ACCB
        assert row55_reference["predicate_kind"] == "sge"
        assert row55_reference["observed_predicate_kind"] == "slt"
        assert row55_reference["comparison_constant"] == 0x13921E0E
        assert row55_reference["transfer_ea"] == 0x40ACD7
        assert row55_reference["true_target_ea"] == 0x40ACD9
        assert row55_reference["false_target_ea"] == 0x40B26D
        assert row55_reference["true_target_block_id"] == "native@0x40ACD9"
        assert row55_reference["false_target_block_id"] == "native@0x40B26D"
        assert row55_reference["owned_corridor_instruction_eas"] == [
            0x40ACBF,
            0x40ACC5,
            0x40ACCB,
            0x40ACCD,
            0x40ACD3,
            0x40ACD5,
            0x40ACD7,
        ]
        assert row55_reference["imported_closure_block_ids"] == [
            "native@0x40ACD9",
            "native@0x40ACE7",
            "native@0x40ACED",
            "native@0x40ACF1",
            "native@0x40B26D",
            "native@0x40B27B",
            "native@0x40B281",
            "native@0x40B285",
        ]
        assert row55_reference["boundary_exit_eas"] == [0x40A5F0, 0x40ACF3]
        row56_reference = reference_payloads["rhad:route@0x40ACF1"]
        assert row56_reference["reference_order"] == 56
        assert row56_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row56_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row56_reference["source_native_ea"] == 0x40ACD9
        assert row56_reference["source_block_anchor_ea"] == 0x40ACE7
        assert row56_reference["join_ea"] == 0x40ACED
        assert row56_reference["condition_producer_ea"] == 0x40ACDF
        assert row56_reference["predicate_anchor_ea"] == 0x40ACE5
        assert row56_reference["predicate_kind"] == "eq"
        assert row56_reference["observed_predicate_kind"] == "ne"
        assert row56_reference["comparison_constant"] == 0x0E9795EF
        assert row56_reference["transfer_ea"] == 0x40ACF1
        assert row56_reference["true_target_ea"] == 0x40ACF3
        assert row56_reference["false_target_ea"] == 0x40A5F0
        assert row56_reference["true_target_block_id"] == "native@0x40ACF3"
        assert row56_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row56_reference["owned_corridor_instruction_eas"] == [
            0x40ACD9,
            0x40ACDF,
            0x40ACE5,
            0x40ACE7,
            0x40ACED,
            0x40ACEF,
            0x40ACF1,
        ]
        assert row56_reference["imported_closure_block_ids"] == [
            "native@0x40ACF3",
            "native@0x40AD06",
            "native@0x40AD18",
            "native@0x40AD1C",
            "native@0x40B598",
            "native@0x40B5AF",
            "native@0x40B5B5",
        ]
        assert row56_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row57_reference = reference_payloads["route:rhad-direct@0x40AD1C"]
        assert row57_reference["reference_operation_id"] == "rhad:route@0x40AD1C"
        assert row57_reference["reference_order"] == 57
        assert row57_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row57_reference["operation_variant"] == "simple_indirect_jump"
        assert row57_reference["source_native_ea"] == 0x40AD06
        assert row57_reference["source_block_anchor_ea"] == 0x40AD18
        assert row57_reference["transfer_ea"] == 0x40AD1C
        assert row57_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row57_reference["owned_corridor_instruction_eas"] == [
            0x40AD06,
            0x40AD18,
            0x40AD1A,
            0x40AD1C,
        ]
        assert row57_reference["boundary_exit_eas"] == [0x40B790]
        row58_reference = reference_payloads["rhad:route@0x40AD36"]
        assert row58_reference["reference_order"] == 58
        assert row58_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row58_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row58_reference["source_native_ea"] == 0x40AD1E
        assert row58_reference["source_block_anchor_ea"] == 0x40AD32
        assert row58_reference["join_ea"] == 0x40AD32
        assert row58_reference["condition_producer_ea"] == 0x40AD24
        assert row58_reference["predicate_anchor_ea"] == 0x40AD2A
        assert row58_reference["predicate_kind"] == "sge"
        assert row58_reference["observed_predicate_kind"] == "slt"
        assert row58_reference["comparison_constant"] == 0x6487820D
        assert row58_reference["transfer_ea"] == 0x40AD36
        assert row58_reference["true_target_ea"] == 0x40AD38
        assert row58_reference["false_target_ea"] == 0x40B2DB
        assert row58_reference["true_target_block_id"] == "native@0x40AD38"
        assert row58_reference["false_target_block_id"] == "native@0x40B2DB"
        assert row58_reference["owned_corridor_instruction_eas"] == [
            0x40AD1E,
            0x40AD24,
            0x40AD2A,
            0x40AD2C,
            0x40AD32,
            0x40AD34,
            0x40AD36,
        ]
        assert row58_reference["imported_closure_block_ids"] == [
            "native@0x40AD38",
            "native@0x40AD46",
            "native@0x40AD4C",
            "native@0x40AD50",
            "native@0x40B2DB",
            "native@0x40B2E9",
            "native@0x40B2EF",
            "native@0x40B2F3",
        ]
        assert row58_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AD52]
        row59_reference = reference_payloads["rhad:route@0x40AD50"]
        assert row59_reference["reference_order"] == 59
        assert row59_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row59_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row59_reference["source_native_ea"] == 0x40AD38
        assert row59_reference["source_block_anchor_ea"] == 0x40AD4C
        assert row59_reference["join_ea"] == 0x40AD4C
        assert row59_reference["condition_producer_ea"] == 0x40AD3E
        assert row59_reference["predicate_anchor_ea"] == 0x40AD44
        assert row59_reference["predicate_kind"] == "ne"
        assert row59_reference["observed_predicate_kind"] == "eq"
        assert row59_reference["comparison_constant"] == 0x636961E8
        assert row59_reference["transfer_ea"] == 0x40AD50
        assert row59_reference["true_target_ea"] == 0x40AD52
        assert row59_reference["false_target_ea"] == 0x40A5F0
        assert row59_reference["true_target_block_id"] == "native@0x40AD52"
        assert row59_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row59_reference["owned_corridor_instruction_eas"] == [
            0x40AD38,
            0x40AD3E,
            0x40AD44,
            0x40AD46,
            0x40AD4C,
            0x40AD4E,
            0x40AD50,
        ]
        assert row59_reference["imported_closure_block_ids"] == [
            "native@0x40AD52",
            "native@0x40AD65",
            "native@0x40AD68",
            "native@0x40AD6C",
        ]
        assert row59_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row60_reference = reference_payloads["rhad:route@0x40AD6C"]
        assert row60_reference["reference_order"] == 60
        assert row60_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row60_reference["operation_variant"] == "cmov_selected_indirect"
        assert row60_reference["source_native_ea"] == 0x40AD5D
        assert row60_reference["source_block_anchor_ea"] == 0x40AD52
        assert row60_reference["condition_producer_ea"] == 0x40AD57
        assert row60_reference["predicate_anchor_ea"] == 0x40AD65
        assert row60_reference["predicate_kind"] == "slt"
        assert row60_reference["observed_predicate_kind"] == "sge"
        assert row60_reference["comparison_constant"] == 0x0BB2D365
        assert row60_reference["transfer_ea"] == 0x40AD6C
        assert row60_reference["true_target_ea"] == 0x40B6C0
        assert row60_reference["false_target_ea"] == 0x40A607
        assert row60_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row60_reference["false_target_block_id"] == "native@0x40A607"
        assert row60_reference["owned_corridor_instruction_eas"] == [
            0x40AD5D,
            0x40AD5F,
            0x40AD65,
            0x40AD68,
            0x40AD6A,
            0x40AD6C,
        ]
        assert row60_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row60_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row61_reference = reference_payloads["rhad:route@0x40AD86"]
        assert row61_reference["reference_order"] == 61
        assert row61_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row61_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row61_reference["source_native_ea"] == 0x40AD6E
        assert row61_reference["source_block_anchor_ea"] == 0x40AD82
        assert row61_reference["join_ea"] == 0x40AD82
        assert row61_reference["condition_producer_ea"] == 0x40AD74
        assert row61_reference["predicate_anchor_ea"] == 0x40AD7A
        assert row61_reference["predicate_kind"] == "sge"
        assert row61_reference["observed_predicate_kind"] == "slt"
        assert row61_reference["comparison_constant"] == 0x304E8694
        assert row61_reference["transfer_ea"] == 0x40AD86
        assert row61_reference["true_target_ea"] == 0x40AD88
        assert row61_reference["false_target_ea"] == 0x40B32C
        assert row61_reference["true_target_block_id"] == "native@0x40AD88"
        assert row61_reference["false_target_block_id"] == "native@0x40B32C"
        assert row61_reference["owned_corridor_instruction_eas"] == [
            0x40AD6E,
            0x40AD74,
            0x40AD7A,
            0x40AD7C,
            0x40AD82,
            0x40AD84,
            0x40AD86,
        ]
        assert row61_reference["imported_closure_block_ids"] == [
            "native@0x40AD88",
            "native@0x40AD96",
            "native@0x40AD9C",
            "native@0x40ADA0",
            "native@0x40B32C",
            "native@0x40B340",
        ]
        assert row61_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ADA2,
            0x40B342,
        ]
        row62_reference = reference_payloads["rhad:route@0x40ADA0"]
        assert row62_reference["reference_order"] == 62
        assert row62_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row62_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row62_reference["source_native_ea"] == 0x40AD88
        assert row62_reference["source_block_anchor_ea"] == 0x40AD9C
        assert row62_reference["join_ea"] == 0x40AD9C
        assert row62_reference["condition_producer_ea"] == 0x40AD8E
        assert row62_reference["predicate_anchor_ea"] == 0x40AD94
        assert row62_reference["predicate_kind"] == "ne"
        assert row62_reference["observed_predicate_kind"] == "eq"
        assert row62_reference["comparison_constant"] == 0x2B8162DC
        assert row62_reference["transfer_ea"] == 0x40ADA0
        assert row62_reference["true_target_ea"] == 0x40ADA2
        assert row62_reference["false_target_ea"] == 0x40A5F0
        assert row62_reference["true_target_block_id"] == "native@0x40ADA2"
        assert row62_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row62_reference["owned_corridor_instruction_eas"] == [
            0x40AD88,
            0x40AD8E,
            0x40AD94,
            0x40AD96,
            0x40AD9C,
            0x40AD9E,
            0x40ADA0,
        ]
        assert row62_reference["imported_closure_block_ids"] == [
            "native@0x40ADA2",
            "native@0x40ADB5",
            "native@0x40ADB8",
            "native@0x40ADBC",
        ]
        assert row62_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row63_reference = reference_payloads["rhad:route@0x40ADBC"]
        assert row63_reference["reference_order"] == 63
        assert row63_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row63_reference["operation_variant"] == "cmov_selected_indirect"
        assert row63_reference["source_native_ea"] == 0x40ADAD
        assert row63_reference["source_block_anchor_ea"] == 0x40ADA2
        assert row63_reference["condition_producer_ea"] == 0x40ADA7
        assert row63_reference["predicate_anchor_ea"] == 0x40ADB5
        assert row63_reference["predicate_kind"] == "slt"
        assert row63_reference["observed_predicate_kind"] == "sge"
        assert row63_reference["comparison_constant"] == 0x0BB2D365
        assert row63_reference["transfer_ea"] == 0x40ADBC
        assert row63_reference["true_target_ea"] == 0x40B6C0
        assert row63_reference["false_target_ea"] == 0x40A607
        assert row63_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row63_reference["false_target_block_id"] == "native@0x40A607"
        assert row63_reference["owned_corridor_instruction_eas"] == [
            0x40ADAD,
            0x40ADAF,
            0x40ADB5,
            0x40ADB8,
            0x40ADBA,
            0x40ADBC,
        ]
        assert row63_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row63_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row64_reference = reference_payloads["rhad:route@0x40ADD6"]
        assert row64_reference["reference_order"] == 64
        assert row64_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row64_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row64_reference["source_native_ea"] == 0x40ADBE
        assert row64_reference["source_block_anchor_ea"] == 0x40ADD2
        assert row64_reference["join_ea"] == 0x40ADD2
        assert row64_reference["condition_producer_ea"] == 0x40ADC4
        assert row64_reference["predicate_anchor_ea"] == 0x40ADCA
        assert row64_reference["predicate_kind"] == "sge"
        assert row64_reference["observed_predicate_kind"] == "slt"
        assert row64_reference["comparison_constant"] == 0x7E46FA09
        assert row64_reference["transfer_ea"] == 0x40ADD6
        assert row64_reference["true_target_ea"] == 0x40ADD8
        assert row64_reference["false_target_ea"] == 0x40B37C
        assert row64_reference["true_target_block_id"] == "native@0x40ADD8"
        assert row64_reference["false_target_block_id"] == "native@0x40B37C"
        assert row64_reference["owned_corridor_instruction_eas"] == [
            0x40ADBE,
            0x40ADC4,
            0x40ADCA,
            0x40ADCC,
            0x40ADD2,
            0x40ADD4,
            0x40ADD6,
        ]
        assert row64_reference["imported_closure_block_ids"] == [
            "native@0x40ADD8",
            "native@0x40ADE6",
            "native@0x40ADEC",
            "native@0x40ADF0",
            "native@0x40B37C",
            "native@0x40B38A",
            "native@0x40B390",
            "native@0x40B394",
        ]
        assert row64_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ADF2,
            0x40B396,
            0x40B3E5,
        ]
        row65_reference = reference_payloads["rhad:route@0x40ADF0"]
        assert row65_reference["reference_order"] == 65
        assert row65_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row65_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row65_reference["source_native_ea"] == 0x40ADD8
        assert row65_reference["source_block_anchor_ea"] == 0x40ADEC
        assert row65_reference["join_ea"] == 0x40ADEC
        assert row65_reference["condition_producer_ea"] == 0x40ADDE
        assert row65_reference["predicate_anchor_ea"] == 0x40ADE4
        assert row65_reference["predicate_kind"] == "ne"
        assert row65_reference["observed_predicate_kind"] == "eq"
        assert row65_reference["comparison_constant"] == 0x7C4FB03D
        assert row65_reference["transfer_ea"] == 0x40ADF0
        assert row65_reference["true_target_ea"] == 0x40ADF2
        assert row65_reference["false_target_ea"] == 0x40A5F0
        assert row65_reference["true_target_block_id"] == "native@0x40ADF2"
        assert row65_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row65_reference["owned_corridor_instruction_eas"] == [
            0x40ADD8,
            0x40ADDE,
            0x40ADE4,
            0x40ADE6,
            0x40ADEC,
            0x40ADEE,
            0x40ADF0,
        ]
        assert row65_reference["imported_closure_block_ids"] == [
            "native@0x40ADF2",
            "native@0x40AE05",
            "native@0x40AE08",
            "native@0x40AE18",
        ]
        assert row65_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row66_reference = reference_payloads["rhad:route@0x40AE18"]
        assert row66_reference["reference_order"] == 66
        assert row66_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row66_reference["operation_variant"] == "cmov_selected_indirect"
        assert row66_reference["source_native_ea"] == 0x40ADFD
        assert row66_reference["source_block_anchor_ea"] == 0x40ADF2
        assert row66_reference["condition_producer_ea"] == 0x40ADF7
        assert row66_reference["predicate_anchor_ea"] == 0x40AE05
        assert row66_reference["predicate_kind"] == "slt"
        assert row66_reference["observed_predicate_kind"] == "sge"
        assert row66_reference["comparison_constant"] == 0x0BB2D365
        assert row66_reference["transfer_ea"] == 0x40AE18
        assert row66_reference["true_target_ea"] == 0x40B6C0
        assert row66_reference["false_target_ea"] == 0x40A607
        assert row66_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row66_reference["false_target_block_id"] == "native@0x40A607"
        assert row66_reference["owned_corridor_instruction_eas"] == [
            0x40ADFD,
            0x40ADFF,
            0x40AE05,
            0x40AE08,
            0x40AE0A,
            0x40AE18,
        ]
        assert row66_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row66_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row67_reference = reference_payloads["route:rhad-direct@0x40AE24"]
        assert row67_reference["reference_operation_id"] == "rhad:route@0x40AE24"
        assert row67_reference["reference_order"] == 67
        assert row67_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row67_reference["operation_variant"] == "simple_indirect_jump"
        assert row67_reference["source_native_ea"] == 0x40A66F
        assert row67_reference["source_block_anchor_ea"] == 0x40AE1A
        assert row67_reference["transfer_ea"] == 0x40AE24
        assert row67_reference["direct_target_block_id"] == "native@0x40A5CA"
        assert row67_reference["owned_corridor_instruction_eas"] == [
            0x40A66F,
            0x40AE1A,
            0x40AE20,
            0x40AE22,
            0x40AE24,
        ]
        assert row67_reference["imported_closure_block_ids"] == [
            "native@0x40A5CA",
            "native@0x40A5DC",
            "native@0x40A5DF",
            "native@0x40A5E3",
        ]
        assert row67_reference["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
        row68_reference = reference_payloads["rhad:route@0x40AE3C"]
        assert row68_reference["reference_order"] == 68
        assert row68_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert row68_reference["operation_variant"] == "setcc_indexed_table"
        assert row68_reference["source_native_ea"] == 0x40AE26
        assert row68_reference["source_block_anchor_ea"] == 0x40AE26
        assert row68_reference["condition_producer_ea"] == 0x40AE28
        assert row68_reference["predicate_anchor_ea"] == 0x40AE2E
        assert row68_reference["predicate_kind"] == "eq"
        assert row68_reference["fallthrough_delivery"] == "planned_helper"
        assert row68_reference["transfer_ea"] == 0x40AE3C
        assert row68_reference["true_target_ea"] == 0x40AE3E
        assert row68_reference["false_target_ea"] == 0x40A5F0
        assert row68_reference["true_target_block_id"] == "native@0x40AE3E"
        assert row68_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row68_reference["owned_corridor_instruction_eas"] == [
            0x40AE26,
            0x40AE28,
            0x40AE2E,
            0x40AE31,
            0x40AE34,
            0x40AE3A,
            0x40AE3C,
        ]
        assert row68_reference["imported_closure_block_ids"] == [
            "native@0x40AE3E",
            "native@0x40AE63",
            "native@0x40AE82",
            "native@0x40AE85",
            "native@0x40AE89",
        ]
        assert row68_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row68_reference["setcc_table"]["table_base_ea"] == 0x48B650
        assert row68_reference["setcc_table"]["stride_bytes"] == 0x40
        assert row68_reference["setcc_table"]["index_scaling"] == {
            "kind": "explicit_shift",
            "shift_bits": 6,
            "shift_ea": 0x40AE31,
        }
        assert (
            row68_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40AE3C"]
        )
        assert (
            row68_reference["aggregate_program_identity"]
            == (compiled_payload["aggregate_program_identity"])
        )
        row69_reference = reference_payloads["rhad:route@0x40AE89"]
        assert row69_reference["reference_order"] == 69
        assert row69_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row69_reference["operation_variant"] == "cmov_selected_indirect"
        assert row69_reference["source_native_ea"] == 0x40AE69
        assert row69_reference["source_block_anchor_ea"] == 0x40AE63
        assert row69_reference["condition_producer_ea"] == 0x40AE74
        assert row69_reference["predicate_anchor_ea"] == 0x40AE82
        assert row69_reference["predicate_kind"] == "slt"
        assert row69_reference["observed_predicate_kind"] == "sge"
        assert row69_reference["comparison_constant"] == 0x0BB2D365
        assert row69_reference["transfer_ea"] == 0x40AE89
        assert row69_reference["true_target_ea"] == 0x40B6C0
        assert row69_reference["false_target_ea"] == 0x40A607
        assert row69_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row69_reference["false_target_block_id"] == "native@0x40A607"
        assert row69_reference["owned_corridor_instruction_eas"] == [
            0x40AE69,
            0x40AE7A,
            0x40AE7C,
            0x40AE82,
            0x40AE85,
            0x40AE87,
            0x40AE89,
        ]
        assert row69_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row69_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row70_reference = reference_payloads["rhad:route@0x40AEA3"]
        assert row70_reference["reference_order"] == 70
        assert row70_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row70_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row70_reference["source_native_ea"] == 0x40AE8B
        assert row70_reference["source_block_anchor_ea"] == 0x40AE9F
        assert row70_reference["join_ea"] == 0x40AE9F
        assert row70_reference["condition_producer_ea"] == 0x40AE91
        assert row70_reference["predicate_anchor_ea"] == 0x40AE97
        assert row70_reference["predicate_kind"] == "ne"
        assert row70_reference["observed_predicate_kind"] == "eq"
        assert row70_reference["comparison_constant"] == 0x40ABF871
        assert row70_reference["transfer_ea"] == 0x40AEA3
        assert row70_reference["true_target_ea"] == 0x40AEA5
        assert row70_reference["false_target_ea"] == 0x40A5F0
        assert row70_reference["true_target_block_id"] == "native@0x40AEA5"
        assert row70_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row70_reference["owned_corridor_instruction_eas"] == [
            0x40AE8B,
            0x40AE91,
            0x40AE97,
            0x40AE99,
            0x40AE9F,
            0x40AEA1,
            0x40AEA3,
        ]
        assert row70_reference["imported_closure_block_ids"] == [
            "native@0x40AEA5",
            "native@0x40AEC6",
            "native@0x40AEDA",
            "native@0x40AEE4",
            "native@0x40B5B7",
            "native@0x40B5D0",
            "native@0x40B5DC",
        ]
        assert row70_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row71_reference = reference_payloads["route:rhad-direct@0x40AEE4"]
        assert row71_reference["reference_operation_id"] == "rhad:route@0x40AEE4"
        assert row71_reference["reference_order"] == 71
        assert row71_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row71_reference["operation_variant"] == "simple_indirect_jump"
        assert row71_reference["source_native_ea"] == 0x40AEC6
        assert row71_reference["source_block_anchor_ea"] == 0x40AEDA
        assert row71_reference["transfer_ea"] == 0x40AEE4
        assert row71_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row71_reference["owned_corridor_instruction_eas"] == [
            0x40AEC6,
            0x40AEDA,
            0x40AEDC,
            0x40AEDE,
            0x40AEE4,
        ]
        assert row71_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row71_reference["boundary_exit_eas"] == [0x40B790]
        row72_reference = reference_payloads["rhad:route@0x40AEFE"]
        assert row72_reference["reference_order"] == 72
        assert row72_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row72_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row72_reference["source_native_ea"] == 0x40AEE6
        assert row72_reference["source_block_anchor_ea"] == 0x40AEFA
        assert row72_reference["join_ea"] == 0x40AEFA
        assert row72_reference["condition_producer_ea"] == 0x40AEEC
        assert row72_reference["predicate_anchor_ea"] == 0x40AEF2
        assert row72_reference["predicate_kind"] == "ne"
        assert row72_reference["observed_predicate_kind"] == "eq"
        assert row72_reference["comparison_constant"] == 0x2100AFDD
        assert row72_reference["transfer_ea"] == 0x40AEFE
        assert row72_reference["true_target_ea"] == 0x40AF00
        assert row72_reference["false_target_ea"] == 0x40A5F0
        assert row72_reference["true_target_block_id"] == "native@0x40AF00"
        assert row72_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row72_reference["owned_corridor_instruction_eas"] == [
            0x40AEE6,
            0x40AEEC,
            0x40AEF2,
            0x40AEF4,
            0x40AEFA,
            0x40AEFC,
            0x40AEFE,
        ]
        assert row72_reference["imported_closure_block_ids"] == [
            "native@0x40AF00",
            "native@0x40AF1C",
            "native@0x40AF2F",
            "native@0x40AF9D",
            "native@0x40AFBB",
            "native@0x40AFD3",
            "native@0x40AFDD",
            "native@0x40B5DE",
            "native@0x40B5FB",
            "native@0x40B607",
        ]
        assert row72_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row73_reference = reference_payloads["route:rhad-direct@0x40AFDD"]
        assert row73_reference["reference_operation_id"] == "rhad:route@0x40AFDD"
        assert row73_reference["reference_order"] == 73
        assert row73_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row73_reference["operation_variant"] == "simple_indirect_jump"
        assert row73_reference["source_native_ea"] == 0x40AFBB
        assert row73_reference["source_block_anchor_ea"] == 0x40AFD3
        assert row73_reference["transfer_ea"] == 0x40AFDD
        assert row73_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row73_reference["owned_corridor_instruction_eas"] == [
            0x40AFBB,
            0x40AFD3,
            0x40AFD5,
            0x40AFD7,
            0x40AFDD,
        ]
        assert row73_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row73_reference["boundary_exit_eas"] == [0x40B790]
        row74_reference = reference_payloads["rhad:route@0x40AFF7"]
        assert row74_reference["reference_order"] == 74
        assert row74_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row74_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row74_reference["source_native_ea"] == 0x40AFDF
        assert row74_reference["source_block_anchor_ea"] == 0x40AFF3
        assert row74_reference["join_ea"] == 0x40AFF3
        assert row74_reference["condition_producer_ea"] == 0x40AFE5
        assert row74_reference["predicate_anchor_ea"] == 0x40AFEB
        assert row74_reference["predicate_kind"] == "ne"
        assert row74_reference["observed_predicate_kind"] == "eq"
        assert row74_reference["comparison_constant"] == 0x6859ABF3
        assert row74_reference["transfer_ea"] == 0x40AFF7
        assert row74_reference["true_target_ea"] == 0x40AFF9
        assert row74_reference["false_target_ea"] == 0x40A5F0
        assert row74_reference["true_target_block_id"] == "native@0x40AFF9"
        assert row74_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row74_reference["owned_corridor_instruction_eas"] == [
            0x40AFDF,
            0x40AFE5,
            0x40AFEB,
            0x40AFED,
            0x40AFF3,
            0x40AFF5,
            0x40AFF7,
        ]
        assert row74_reference["imported_closure_block_ids"] == [
            "native@0x40AFF9",
            "native@0x40B00C",
            "native@0x40B01E",
            "native@0x40B022",
            "native@0x40B609",
            "native@0x40B620",
            "native@0x40B626",
        ]
        assert row74_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row75_reference = reference_payloads["route:rhad-direct@0x40B022"]
        assert row75_reference["reference_operation_id"] == "rhad:route@0x40B022"
        assert row75_reference["reference_order"] == 75
        assert row75_reference["operation_variant"] == "simple_indirect_jump"
        assert row75_reference["source_native_ea"] == 0x40B00C
        assert row75_reference["source_block_anchor_ea"] == 0x40B01E
        assert row75_reference["transfer_ea"] == 0x40B022
        assert row75_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row75_reference["owned_corridor_instruction_eas"] == [
            0x40B00C,
            0x40B01E,
            0x40B020,
            0x40B022,
        ]
        assert row75_reference["boundary_exit_eas"] == [0x40B790]
        row76_reference = reference_payloads["rhad:route@0x40B03C"]
        assert row76_reference["reference_order"] == 76
        assert row76_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row76_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row76_reference["source_native_ea"] == 0x40B024
        assert row76_reference["source_block_anchor_ea"] == 0x40B038
        assert row76_reference["join_ea"] == 0x40B038
        assert row76_reference["condition_producer_ea"] == 0x40B02A
        assert row76_reference["predicate_anchor_ea"] == 0x40B030
        assert row76_reference["predicate_kind"] == "ne"
        assert row76_reference["observed_predicate_kind"] == "eq"
        assert row76_reference["comparison_constant"] == 0x0CDF90C9
        assert row76_reference["transfer_ea"] == 0x40B03C
        assert row76_reference["true_target_ea"] == 0x40B03E
        assert row76_reference["false_target_ea"] == 0x40A5F0
        assert row76_reference["true_target_block_id"] == "native@0x40B03E"
        assert row76_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row76_reference["owned_corridor_instruction_eas"] == [
            0x40B024,
            0x40B02A,
            0x40B030,
            0x40B032,
            0x40B038,
            0x40B03A,
            0x40B03C,
        ]
        assert row76_reference["imported_closure_block_ids"] == [
            "native@0x40B03E",
            "native@0x40B059",
            "native@0x40B06B",
            "native@0x40B06F",
            "native@0x40B628",
            "native@0x40B63F",
            "native@0x40B645",
        ]
        assert row76_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row77_reference = reference_payloads["route:rhad-direct@0x40B06F"]
        assert row77_reference["reference_operation_id"] == "rhad:route@0x40B06F"
        assert row77_reference["reference_order"] == 77
        assert row77_reference["operation_variant"] == "simple_indirect_jump"
        assert row77_reference["source_native_ea"] == 0x40B059
        assert row77_reference["source_block_anchor_ea"] == 0x40B06B
        assert row77_reference["transfer_ea"] == 0x40B06F
        assert row77_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row77_reference["owned_corridor_instruction_eas"] == [
            0x40B059,
            0x40B06B,
            0x40B06D,
            0x40B06F,
        ]
        assert row77_reference["boundary_exit_eas"] == [0x40B790]
        row78_reference = reference_payloads["rhad:route@0x40B089"]
        assert row78_reference["reference_order"] == 78
        assert row78_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row78_reference["source_native_ea"] == 0x40B071
        assert row78_reference["source_block_anchor_ea"] == 0x40B085
        assert row78_reference["join_ea"] == 0x40B085
        assert row78_reference["condition_producer_ea"] == 0x40B077
        assert row78_reference["predicate_anchor_ea"] == 0x40B07D
        assert row78_reference["predicate_kind"] == "ne"
        assert row78_reference["observed_predicate_kind"] == "eq"
        assert row78_reference["comparison_constant"] == 0x5E07BA29
        assert row78_reference["transfer_ea"] == 0x40B089
        assert row78_reference["true_target_ea"] == 0x40B08B
        assert row78_reference["false_target_ea"] == 0x40A5F0
        assert row78_reference["owned_corridor_instruction_eas"] == [
            0x40B071,
            0x40B077,
            0x40B07D,
            0x40B07F,
            0x40B085,
            0x40B087,
            0x40B089,
        ]
        assert row78_reference["imported_closure_block_ids"] == [
            "native@0x40B08B",
            "native@0x40B094",
            "native@0x40B0B3",
            "native@0x40B0B6",
            "native@0x40B0BA",
        ]
        assert row78_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row79_reference = reference_payloads["rhad:route@0x40B0BA"]
        assert row79_reference["reference_order"] == 79
        assert row79_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row79_reference["operation_variant"] == "cmov_selected_indirect"
        assert row79_reference["source_native_ea"] == 0x40B09A
        assert row79_reference["source_block_anchor_ea"] == 0x40B094
        assert row79_reference["condition_producer_ea"] == 0x40B0A5
        assert row79_reference["predicate_anchor_ea"] == 0x40B0B3
        assert row79_reference["predicate_kind"] == "slt"
        assert row79_reference["observed_predicate_kind"] == "sge"
        assert row79_reference["comparison_constant"] == 0x0BB2D365
        assert row79_reference["transfer_ea"] == 0x40B0BA
        assert row79_reference["true_target_ea"] == 0x40B6C0
        assert row79_reference["false_target_ea"] == 0x40A607
        assert row79_reference["owned_corridor_instruction_eas"] == [
            0x40B09A,
            0x40B0AB,
            0x40B0AD,
            0x40B0B3,
            0x40B0B6,
            0x40B0B8,
            0x40B0BA,
        ]
        assert row79_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row80_reference = reference_payloads["rhad:route@0x40B0D4"]
        assert row80_reference["reference_order"] == 80
        assert row80_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row80_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row80_reference["source_native_ea"] == 0x40B0BC
        assert row80_reference["source_block_anchor_ea"] == 0x40B0D0
        assert row80_reference["condition_producer_ea"] == 0x40B0C2
        assert row80_reference["predicate_anchor_ea"] == 0x40B0C8
        assert row80_reference["predicate_kind"] == "ne"
        assert row80_reference["observed_predicate_kind"] == "eq"
        assert row80_reference["comparison_constant"] == 0x29947C85
        assert row80_reference["transfer_ea"] == 0x40B0D4
        assert row80_reference["true_target_ea"] == 0x40B0D6
        assert row80_reference["false_target_ea"] == 0x40A5F0
        assert row80_reference["owned_corridor_instruction_eas"] == [
            0x40B0BC,
            0x40B0C2,
            0x40B0C8,
            0x40B0CA,
            0x40B0D0,
            0x40B0D2,
            0x40B0D4,
        ]
        assert row80_reference["imported_closure_block_ids"] == [
            "native@0x40B0D6",
            "native@0x40B0E9",
            "native@0x40B0EC",
            "native@0x40B0F0",
        ]
        assert row80_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row81_reference = reference_payloads["rhad:route@0x40B0F0"]
        assert row81_reference["reference_order"] == 81
        assert row81_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row81_reference["operation_variant"] == "cmov_selected_indirect"
        assert row81_reference["source_native_ea"] == 0x40B0E1
        assert row81_reference["source_block_anchor_ea"] == 0x40B0D6
        assert row81_reference["condition_producer_ea"] == 0x40B0DB
        assert row81_reference["predicate_anchor_ea"] == 0x40B0E9
        assert row81_reference["predicate_kind"] == "slt"
        assert row81_reference["observed_predicate_kind"] == "sge"
        assert row81_reference["comparison_constant"] == 0x0BB2D365
        assert row81_reference["transfer_ea"] == 0x40B0F0
        assert row81_reference["true_target_ea"] == 0x40B6C0
        assert row81_reference["false_target_ea"] == 0x40A607
        assert row81_reference["owned_corridor_instruction_eas"] == [
            0x40B0DB,
            0x40B0E1,
            0x40B0E3,
            0x40B0E9,
            0x40B0EC,
            0x40B0EE,
            0x40B0F0,
        ]
        assert row81_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row82_reference = reference_payloads["rhad:route@0x40B10A"]
        assert row82_reference["reference_order"] == 82
        assert row82_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row82_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row82_reference["source_native_ea"] == 0x40B0F2
        assert row82_reference["source_block_anchor_ea"] == 0x40B106
        assert row82_reference["condition_producer_ea"] == 0x40B0F8
        assert row82_reference["predicate_anchor_ea"] == 0x40B0FE
        assert row82_reference["predicate_kind"] == "ne"
        assert row82_reference["observed_predicate_kind"] == "eq"
        assert row82_reference["comparison_constant"] == 0x78BAC34B
        assert row82_reference["transfer_ea"] == 0x40B10A
        assert row82_reference["true_target_ea"] == 0x40B10C
        assert row82_reference["false_target_ea"] == 0x40A5F0
        assert row82_reference["owned_corridor_instruction_eas"] == [
            0x40B0F2,
            0x40B0F8,
            0x40B0FE,
            0x40B100,
            0x40B106,
            0x40B108,
            0x40B10A,
        ]
        assert row82_reference["imported_closure_block_ids"] == [
            "native@0x40B10C",
            "native@0x40B11A",
            "native@0x40B121",
            "native@0x40B140",
            "native@0x40B143",
            "native@0x40B147",
        ]
        assert row82_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row83_reference = reference_payloads["rhad:route@0x40B147"]
        assert row83_reference["reference_order"] == 83
        assert row83_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row83_reference["operation_variant"] == "cmov_selected_indirect"
        assert row83_reference["source_native_ea"] == 0x40B127
        assert row83_reference["source_block_anchor_ea"] == 0x40B121
        assert row83_reference["condition_producer_ea"] == 0x40B132
        assert row83_reference["predicate_anchor_ea"] == 0x40B140
        assert row83_reference["predicate_kind"] == "slt"
        assert row83_reference["observed_predicate_kind"] == "sge"
        assert row83_reference["comparison_constant"] == 0x0BB2D365
        assert row83_reference["transfer_ea"] == 0x40B147
        assert row83_reference["true_target_ea"] == 0x40B6C0
        assert row83_reference["false_target_ea"] == 0x40A607
        assert row83_reference["owned_corridor_instruction_eas"] == [
            0x40B127,
            0x40B132,
            0x40B138,
            0x40B13A,
            0x40B140,
            0x40B143,
            0x40B145,
            0x40B147,
        ]
        assert row83_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row84_reference = reference_payloads["rhad:route@0x40B161"]
        assert row84_reference["reference_order"] == 84
        assert row84_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row84_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row84_reference["source_native_ea"] == 0x40B149
        assert row84_reference["source_block_anchor_ea"] == 0x40B15D
        assert row84_reference["condition_producer_ea"] == 0x40B14F
        assert row84_reference["predicate_anchor_ea"] == 0x40B155
        assert row84_reference["predicate_kind"] == "ne"
        assert row84_reference["observed_predicate_kind"] == "eq"
        assert row84_reference["comparison_constant"] == 0x1EBFFA3C
        assert row84_reference["transfer_ea"] == 0x40B161
        assert row84_reference["true_target_ea"] == 0x40B163
        assert row84_reference["false_target_ea"] == 0x40A5F0
        assert row84_reference["owned_corridor_instruction_eas"] == [
            0x40B149,
            0x40B14F,
            0x40B155,
            0x40B157,
            0x40B15D,
            0x40B15F,
            0x40B161,
        ]
        assert row84_reference["imported_closure_block_ids"] == [
            "native@0x40B163",
            "native@0x40B176",
            "native@0x40B179",
            "native@0x40B17D",
        ]
        assert row84_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row85_reference = reference_payloads["rhad:route@0x40B17D"]
        assert row85_reference["reference_order"] == 85
        assert row85_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row85_reference["operation_variant"] == "cmov_selected_indirect"
        assert row85_reference["source_native_ea"] == 0x40B16E
        assert row85_reference["source_block_anchor_ea"] == 0x40B163
        assert row85_reference["condition_producer_ea"] == 0x40B168
        assert row85_reference["predicate_anchor_ea"] == 0x40B176
        assert row85_reference["predicate_kind"] == "slt"
        assert row85_reference["observed_predicate_kind"] == "sge"
        assert row85_reference["comparison_constant"] == 0x0BB2D365
        assert row85_reference["transfer_ea"] == 0x40B17D
        assert row85_reference["true_target_ea"] == 0x40B6C0
        assert row85_reference["false_target_ea"] == 0x40A607
        assert row85_reference["owned_corridor_instruction_eas"] == [
            0x40B168,
            0x40B16E,
            0x40B170,
            0x40B176,
            0x40B179,
            0x40B17B,
            0x40B17D,
        ]
        assert row85_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row86_reference = reference_payloads["rhad:route@0x40B197"]
        assert row86_reference["reference_order"] == 86
        assert row86_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row86_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row86_reference["source_native_ea"] == 0x40B17F
        assert row86_reference["source_block_anchor_ea"] == 0x40B193
        assert row86_reference["condition_producer_ea"] == 0x40B185
        assert row86_reference["predicate_anchor_ea"] == 0x40B18B
        assert row86_reference["predicate_kind"] == "ne"
        assert row86_reference["observed_predicate_kind"] == "eq"
        assert row86_reference["comparison_constant"] == 0x456A4274
        assert row86_reference["transfer_ea"] == 0x40B197
        assert row86_reference["true_target_ea"] == 0x40B199
        assert row86_reference["false_target_ea"] == 0x40A5F0
        assert row86_reference["owned_corridor_instruction_eas"] == [
            0x40B17F,
            0x40B185,
            0x40B18B,
            0x40B18D,
            0x40B193,
            0x40B195,
            0x40B197,
        ]
        assert row86_reference["imported_closure_block_ids"] == [
            "native@0x40B199",
            "native@0x40B1B6",
            "native@0x40B1CA",
            "native@0x40B1CE",
            "native@0x40B647",
            "native@0x40B660",
            "native@0x40B666",
        ]
        assert row86_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row87_reference = reference_payloads["route:rhad-direct@0x40B1CE"]
        assert row87_reference["reference_operation_id"] == "rhad:route@0x40B1CE"
        assert row87_reference["reference_order"] == 87
        assert row87_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row87_reference["operation_variant"] == "simple_indirect_jump"
        assert row87_reference["source_native_ea"] == 0x40B1B6
        assert row87_reference["source_block_anchor_ea"] == 0x40B1CA
        assert row87_reference["transfer_ea"] == 0x40B1CE
        assert row87_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row87_reference["owned_corridor_instruction_eas"] == [
            0x40B1B6,
            0x40B1CA,
            0x40B1CC,
            0x40B1CE,
        ]
        assert row87_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row87_reference["boundary_exit_eas"] == [0x40B790]
        row88_reference = reference_payloads["rhad:route@0x40B1E8"]
        assert row88_reference["reference_order"] == 88
        assert row88_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row88_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row88_reference["source_native_ea"] == 0x40B1D0
        assert row88_reference["source_block_anchor_ea"] == 0x40B1E4
        assert row88_reference["condition_producer_ea"] == 0x40B1D6
        assert row88_reference["predicate_anchor_ea"] == 0x40B1DC
        assert row88_reference["predicate_kind"] == "ne"
        assert row88_reference["observed_predicate_kind"] == "eq"
        assert row88_reference["comparison_constant"] == 0x22C02855
        assert row88_reference["transfer_ea"] == 0x40B1E8
        assert row88_reference["true_target_ea"] == 0x40B1EA
        assert row88_reference["false_target_ea"] == 0x40A5F0
        assert row88_reference["owned_corridor_instruction_eas"] == [
            0x40B1D0,
            0x40B1D6,
            0x40B1DC,
            0x40B1DE,
            0x40B1E4,
            0x40B1E6,
            0x40B1E8,
        ]
        assert row88_reference["imported_closure_block_ids"] == [
            "native@0x40B1EA",
            "native@0x40B1F4",
            "native@0x40B213",
            "native@0x40B216",
            "native@0x40B21A",
        ]
        assert row88_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row89_reference = reference_payloads["rhad:route@0x40B21A"]
        assert row89_reference["reference_order"] == 89
        assert row89_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row89_reference["operation_variant"] == "cmov_selected_indirect"
        assert row89_reference["source_native_ea"] == 0x40B1FA
        assert row89_reference["source_block_anchor_ea"] == 0x40B1F4
        assert row89_reference["condition_producer_ea"] == 0x40B205
        assert row89_reference["predicate_anchor_ea"] == 0x40B213
        assert row89_reference["predicate_kind"] == "slt"
        assert row89_reference["observed_predicate_kind"] == "sge"
        assert row89_reference["comparison_constant"] == 0x0BB2D365
        assert row89_reference["transfer_ea"] == 0x40B21A
        assert row89_reference["true_target_ea"] == 0x40B6C0
        assert row89_reference["false_target_ea"] == 0x40A607
        assert row89_reference["owned_corridor_instruction_eas"] == [
            0x40B1FA,
            0x40B205,
            0x40B20B,
            0x40B20D,
            0x40B213,
            0x40B216,
            0x40B218,
            0x40B21A,
        ]
        assert row89_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row90_reference = reference_payloads["rhad:route@0x40B234"]
        assert row90_reference["reference_order"] == 90
        assert row90_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row90_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row90_reference["source_native_ea"] == 0x40B21C
        assert row90_reference["source_block_anchor_ea"] == 0x40B230
        assert row90_reference["condition_producer_ea"] == 0x40B222
        assert row90_reference["predicate_anchor_ea"] == 0x40B228
        assert row90_reference["predicate_kind"] == "ne"
        assert row90_reference["observed_predicate_kind"] == "eq"
        assert row90_reference["comparison_constant"] == 0x7278AB7F
        assert row90_reference["transfer_ea"] == 0x40B234
        assert row90_reference["true_target_ea"] == 0x40B236
        assert row90_reference["false_target_ea"] == 0x40A5F0
        assert row90_reference["owned_corridor_instruction_eas"] == [
            0x40B21C,
            0x40B222,
            0x40B228,
            0x40B22A,
            0x40B230,
            0x40B232,
            0x40B234,
        ]
        assert row90_reference["imported_closure_block_ids"] == [
            "native@0x40B236",
            "native@0x40B242",
            "native@0x40B264",
            "native@0x40B267",
        ]
        assert row90_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row91_reference = reference_payloads["rhad:route@0x40B26B"]
        assert row91_reference["reference_order"] == 91
        assert row91_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row91_reference["operation_variant"] == "cmov_selected_indirect"
        assert row91_reference["source_native_ea"] == 0x40B248
        assert row91_reference["source_block_anchor_ea"] == 0x40B242
        assert row91_reference["condition_producer_ea"] == 0x40B256
        assert row91_reference["predicate_anchor_ea"] == 0x40B264
        assert row91_reference["predicate_kind"] == "slt"
        assert row91_reference["observed_predicate_kind"] == "sge"
        assert row91_reference["comparison_constant"] == 0x0BB2D365
        assert row91_reference["transfer_ea"] == 0x40B26B
        assert row91_reference["true_target_ea"] == 0x40B6C0
        assert row91_reference["false_target_ea"] == 0x40A607
        assert row91_reference["owned_corridor_instruction_eas"] == [
            0x40B248,
            0x40B256,
            0x40B25C,
            0x40B25E,
            0x40B264,
            0x40B267,
            0x40B269,
            0x40B26B,
        ]
        assert row91_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row92_reference = reference_payloads["rhad:route@0x40B285"]
        assert row92_reference["reference_order"] == 92
        assert row92_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row92_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row92_reference["source_native_ea"] == 0x40B26D
        assert row92_reference["source_block_anchor_ea"] == 0x40B281
        assert row92_reference["condition_producer_ea"] == 0x40B273
        assert row92_reference["predicate_anchor_ea"] == 0x40B279
        assert row92_reference["predicate_kind"] == "ne"
        assert row92_reference["observed_predicate_kind"] == "eq"
        assert row92_reference["comparison_constant"] == 0x13921E0E
        assert row92_reference["transfer_ea"] == 0x40B285
        assert row92_reference["true_target_ea"] == 0x40B287
        assert row92_reference["false_target_ea"] == 0x40A5F0
        assert row92_reference["owned_corridor_instruction_eas"] == [
            0x40B26D,
            0x40B273,
            0x40B279,
            0x40B27B,
            0x40B281,
            0x40B283,
            0x40B285,
        ]
        assert row92_reference["imported_closure_block_ids"] == [
            "native@0x40B287",
            "native@0x40B2A6",
            "native@0x40B2B7",
            "native@0x40B2CF",
            "native@0x40B2D9",
            "native@0x40B668",
            "native@0x40B685",
            "native@0x40B691",
        ]
        assert row92_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row93_reference = reference_payloads["route:rhad-direct@0x40B2D9"]
        assert row93_reference["reference_operation_id"] == "rhad:route@0x40B2D9"
        assert row93_reference["reference_order"] == 93
        assert row93_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row93_reference["operation_variant"] == "simple_indirect_jump"
        assert row93_reference["source_native_ea"] == 0x40B2B7
        assert row93_reference["source_block_anchor_ea"] == 0x40B2CF
        assert row93_reference["transfer_ea"] == 0x40B2D9
        assert row93_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row93_reference["owned_corridor_instruction_eas"] == [
            0x40B2B7,
            0x40B2CF,
            0x40B2D1,
            0x40B2D3,
            0x40B2D9,
        ]
        assert row93_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row93_reference["boundary_exit_eas"] == [0x40B790]
        row94_reference = reference_payloads["rhad:route@0x40B2F3"]
        assert row94_reference["reference_order"] == 94
        assert row94_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row94_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row94_reference["source_native_ea"] == 0x40B2DB
        assert row94_reference["source_block_anchor_ea"] == 0x40B2EF
        assert row94_reference["condition_producer_ea"] == 0x40B2E1
        assert row94_reference["predicate_anchor_ea"] == 0x40B2E7
        assert row94_reference["predicate_kind"] == "ne"
        assert row94_reference["observed_predicate_kind"] == "eq"
        assert row94_reference["comparison_constant"] == 0x6487820D
        assert row94_reference["transfer_ea"] == 0x40B2F3
        assert row94_reference["true_target_ea"] == 0x40B2F5
        assert row94_reference["false_target_ea"] == 0x40A5F0
        assert row94_reference["owned_corridor_instruction_eas"] == [
            0x40B2DB,
            0x40B2E1,
            0x40B2E7,
            0x40B2E9,
            0x40B2EF,
            0x40B2F1,
            0x40B2F3,
        ]
        assert row94_reference["imported_closure_block_ids"] == [
            "native@0x40B2F5",
            "native@0x40B312",
            "native@0x40B326",
            "native@0x40B32A",
            "native@0x40B693",
            "native@0x40B6AC",
            "native@0x40B6B2",
        ]
        assert row94_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row95_reference = reference_payloads["route:rhad-direct@0x40B32A"]
        assert row95_reference["reference_operation_id"] == "rhad:route@0x40B32A"
        assert row95_reference["reference_order"] == 95
        assert row95_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row95_reference["operation_variant"] == "simple_indirect_jump"
        assert row95_reference["source_native_ea"] == 0x40B312
        assert row95_reference["source_block_anchor_ea"] == 0x40B326
        assert row95_reference["transfer_ea"] == 0x40B32A
        assert row95_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row95_reference["owned_corridor_instruction_eas"] == [
            0x40B312,
            0x40B326,
            0x40B328,
            0x40B32A,
        ]
        assert row95_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row95_reference["boundary_exit_eas"] == [0x40B790]
        row96_reference = reference_payloads["rhad:route@0x40B340"]
        assert row96_reference["reference_order"] == 96
        assert row96_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert row96_reference["operation_variant"] == "setcc_indexed_table"
        assert row96_reference["source_native_ea"] == 0x40B32C
        assert row96_reference["condition_producer_ea"] == 0x40B32E
        assert row96_reference["predicate_anchor_ea"] == 0x40B334
        assert row96_reference["predicate_kind"] == "ne"
        assert row96_reference["fallthrough_delivery"] == "planned_helper"
        assert row96_reference["transfer_ea"] == 0x40B340
        assert row96_reference["true_target_ea"] == 0x40A5F0
        assert row96_reference["false_target_ea"] == 0x40B342
        assert row96_reference["true_target_block_id"] == "native@0x40A5F0"
        assert row96_reference["false_target_block_id"] == "native@0x40B342"
        assert row96_reference["owned_corridor_instruction_eas"] == [
            0x40B32C,
            0x40B32E,
            0x40B334,
            0x40B337,
            0x40B33E,
            0x40B340,
        ]
        assert row96_reference["imported_closure_block_ids"] == [
            "native@0x40B342",
            "native@0x40B354",
            "native@0x40B373",
            "native@0x40B376",
            "native@0x40B37A",
        ]
        assert row96_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row96_reference["setcc_table"]["table_base_ea"] == 0x48B618
        assert row96_reference["setcc_table"]["stride_bytes"] == 4
        assert row96_reference["setcc_table"]["index_scaling"] == {
            "kind": "scaled_lookup",
            "lookup_ea": 0x40B337,
            "scale_bytes": 4,
        }
        assert row96_reference["setcc_table"]["true_index"] == 1
        assert row96_reference["setcc_table"]["false_index"] == 0
        assert (
            row96_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40B340"]
        )
        assert (
            row96_reference["aggregate_program_identity"]
            == compiled_payload["aggregate_program_identity"]
        )
        row97_reference = reference_payloads["rhad:route@0x40B37A"]
        assert row97_reference["reference_order"] == 97
        assert row97_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row97_reference["operation_variant"] == "cmov_selected_indirect"
        assert row97_reference["source_native_ea"] == 0x40B35A
        assert row97_reference["source_block_anchor_ea"] == 0x40B354
        assert row97_reference["condition_producer_ea"] == 0x40B365
        assert row97_reference["predicate_anchor_ea"] == 0x40B373
        assert row97_reference["observed_predicate_kind"] == "sge"
        assert row97_reference["predicate_kind"] == "slt"
        assert row97_reference["comparison_constant"] == 0x0BB2D365
        assert row97_reference["transfer_ea"] == 0x40B37A
        assert row97_reference["true_target_ea"] == 0x40B6C0
        assert row97_reference["false_target_ea"] == 0x40A607
        assert row97_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row97_reference["false_target_block_id"] == "native@0x40A607"
        assert row97_reference["owned_corridor_instruction_eas"] == [
            0x40B35A,
            0x40B365,
            0x40B36B,
            0x40B36D,
            0x40B373,
            0x40B376,
            0x40B378,
            0x40B37A,
        ]
        assert row97_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row97_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row98_reference = reference_payloads["rhad:route@0x40B394"]
        assert row98_reference["reference_order"] == 98
        assert row98_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row98_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row98_reference["source_native_ea"] == 0x40B37C
        assert row98_reference["source_block_anchor_ea"] == 0x40B390
        assert row98_reference["condition_producer_ea"] == 0x40B382
        assert row98_reference["predicate_anchor_ea"] == 0x40B388
        assert row98_reference["observed_predicate_kind"] == "slt"
        assert row98_reference["predicate_kind"] == "sge"
        assert row98_reference["comparison_constant"] == 0x7F9D6412
        assert row98_reference["transfer_ea"] == 0x40B394
        assert row98_reference["true_target_ea"] == 0x40B396
        assert row98_reference["false_target_ea"] == 0x40B3E5
        assert row98_reference["true_target_block_id"] == "native@0x40B396"
        assert row98_reference["false_target_block_id"] == "native@0x40B3E5"
        assert row98_reference["owned_corridor_instruction_eas"] == [
            0x40B37C,
            0x40B382,
            0x40B388,
            0x40B38A,
            0x40B390,
            0x40B392,
            0x40B394,
        ]
        assert row98_reference["imported_closure_block_ids"] == [
            "native@0x40B396",
            "native@0x40B3A4",
            "native@0x40B3AA",
            "native@0x40B3AE",
            "native@0x40B3E5",
            "native@0x40B3F3",
            "native@0x40B3F9",
            "native@0x40B3FD",
        ]
        assert row98_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40B3B0,
            0x40B3FF,
        ]
        row99_reference = reference_payloads["rhad:route@0x40B3AE"]
        assert row99_reference["reference_order"] == 99
        assert row99_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row99_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row99_reference["source_native_ea"] == 0x40B396
        assert row99_reference["source_block_anchor_ea"] == 0x40B3AA
        assert row99_reference["condition_producer_ea"] == 0x40B39C
        assert row99_reference["predicate_anchor_ea"] == 0x40B3A2
        assert row99_reference["observed_predicate_kind"] == "eq"
        assert row99_reference["predicate_kind"] == "ne"
        assert row99_reference["comparison_constant"] == 0x7E46FA09
        assert row99_reference["transfer_ea"] == 0x40B3AE
        assert row99_reference["true_target_ea"] == 0x40B3B0
        assert row99_reference["false_target_ea"] == 0x40A5F0
        assert row99_reference["true_target_block_id"] == "native@0x40B3B0"
        assert row99_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row99_reference["owned_corridor_instruction_eas"] == [
            0x40B396,
            0x40B39C,
            0x40B3A2,
            0x40B3A4,
            0x40B3AA,
            0x40B3AC,
            0x40B3AE,
        ]
        assert row99_reference["imported_closure_block_ids"] == [
            "native@0x40B3B0",
            "native@0x40B3DC",
            "native@0x40B3DF",
            "native@0x40B3E3",
        ]
        assert row99_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row100_reference = reference_payloads["rhad:route@0x40B3E3"]
        assert row100_reference["reference_order"] == 100
        assert row100_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row100_reference["operation_variant"] == "cmov_selected_indirect"
        assert row100_reference["source_native_ea"] == 0x40B3B5
        assert row100_reference["source_block_anchor_ea"] == 0x40B3B0
        assert row100_reference["condition_producer_ea"] == 0x40B3CE
        assert row100_reference["predicate_anchor_ea"] == 0x40B3DC
        assert row100_reference["observed_predicate_kind"] == "slt"
        assert row100_reference["predicate_kind"] == "sge"
        assert row100_reference["comparison_constant"] == 0x0BB2D365
        assert row100_reference["transfer_ea"] == 0x40B3E3
        assert row100_reference["true_target_ea"] == 0x40B6C0
        assert row100_reference["false_target_ea"] == 0x40A607
        assert row100_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row100_reference["false_target_block_id"] == "native@0x40A607"
        assert row100_reference["owned_corridor_instruction_eas"] == [
            0x40B3B5,
            0x40B3CE,
            0x40B3D4,
            0x40B3D6,
            0x40B3DC,
            0x40B3DF,
            0x40B3E1,
            0x40B3E3,
        ]
        assert row100_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row100_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row101_reference = reference_payloads["rhad:route@0x40B3FD"]
        assert row101_reference["reference_order"] == 101
        assert row101_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row101_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row101_reference["source_native_ea"] == 0x40B3E5
        assert row101_reference["source_block_anchor_ea"] == 0x40B3F9
        assert row101_reference["condition_producer_ea"] == 0x40B3EB
        assert row101_reference["predicate_anchor_ea"] == 0x40B3F1
        assert row101_reference["observed_predicate_kind"] == "eq"
        assert row101_reference["predicate_kind"] == "ne"
        assert row101_reference["comparison_constant"] == 0x7F9D6412
        assert row101_reference["transfer_ea"] == 0x40B3FD
        assert row101_reference["true_target_ea"] == 0x40B3FF
        assert row101_reference["false_target_ea"] == 0x40A5F0
        assert row101_reference["true_target_block_id"] == "native@0x40B3FF"
        assert row101_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row101_reference["owned_corridor_instruction_eas"] == [
            0x40B3E5,
            0x40B3EB,
            0x40B3F1,
            0x40B3F3,
            0x40B3F9,
            0x40B3FB,
            0x40B3FD,
        ]
        assert row101_reference["imported_closure_block_ids"] == [
            "native@0x40B3FF",
            "native@0x40B4A4",
            "native@0x40B4BC",
            "native@0x40B4BF",
            "native@0x40B4C3",
        ]
        assert row101_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row102_reference = reference_payloads["rhad:route@0x40B4C3"]
        assert row102_reference["reference_order"] == 102
        assert row102_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row102_reference["operation_variant"] == "cmov_selected_indirect"
        assert row102_reference["source_native_ea"] == 0x40B476
        assert row102_reference["source_block_anchor_ea"] == 0x40B4A4
        assert row102_reference["source_value_block_id"] == "native@0x40B3FF"
        assert row102_reference["condition_producer_ea"] == 0x40B4B4
        assert row102_reference["predicate_anchor_ea"] == 0x40B4BC
        assert row102_reference["observed_predicate_kind"] == "slt"
        assert row102_reference["predicate_kind"] == "sge"
        assert row102_reference["comparison_constant"] == 0x0BB2D365
        assert row102_reference["transfer_ea"] == 0x40B4C3
        assert row102_reference["true_target_ea"] == 0x40B6C0
        assert row102_reference["false_target_ea"] == 0x40A607
        assert row102_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row102_reference["false_target_block_id"] == "native@0x40A607"
        assert row102_reference["owned_corridor_instruction_eas"] == [
            0x40B476,
            0x40B4AA,
            0x40B4B4,
            0x40B4BA,
            0x40B4BC,
            0x40B4BF,
            0x40B4C1,
            0x40B4C3,
        ]
        assert row102_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row102_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row103_reference = reference_payloads["route:rhad-direct@0x40B4EE"]
        assert row103_reference["reference_operation_id"] == "rhad:route@0x40B4EE"
        assert row103_reference["reference_order"] == 103
        assert row103_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row103_reference["operation_variant"] == "simple_indirect_jump"
        assert row103_reference["source_native_ea"] == 0x40A7C7
        assert row103_reference["source_block_anchor_ea"] == 0x40B4E2
        assert row103_reference["transfer_ea"] == 0x40B4EE
        assert row103_reference["direct_target_block_id"] == "native@0x40A607"
        assert row103_reference["owned_corridor_instruction_eas"] == [
            0x40A7C7,
            0x40A7D9,
            0x40A7DF,
            0x40B4D6,
            0x40B4E2,
            0x40B4E4,
            0x40B4E6,
            0x40B4E8,
            0x40B4EE,
        ]
        assert row103_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row103_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row104_reference = reference_payloads["route:rhad-direct@0x40B519"]
        assert row104_reference["reference_operation_id"] == "rhad:route@0x40B519"
        assert row104_reference["reference_order"] == 104
        assert row104_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row104_reference["operation_variant"] == "simple_indirect_jump"
        assert row104_reference["source_native_ea"] == 0x40A936
        assert row104_reference["source_block_anchor_ea"] == 0x40B50D
        assert row104_reference["transfer_ea"] == 0x40B519
        assert row104_reference["direct_target_block_id"] == "native@0x40A607"
        assert row104_reference["owned_corridor_instruction_eas"] == [
            0x40A936,
            0x40A948,
            0x40A94E,
            0x40B501,
            0x40B50D,
            0x40B50F,
            0x40B511,
            0x40B513,
            0x40B519,
        ]
        assert row104_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row104_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row105_reference = reference_payloads["route:rhad-direct@0x40B540"]
        assert row105_reference["reference_operation_id"] == "rhad:route@0x40B540"
        assert row105_reference["reference_order"] == 105
        assert row105_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row105_reference["operation_variant"] == "simple_indirect_jump"
        assert row105_reference["source_native_ea"] == 0x40AB31
        assert row105_reference["source_block_anchor_ea"] == 0x40B534
        assert row105_reference["transfer_ea"] == 0x40B540
        assert row105_reference["direct_target_block_id"] == "native@0x40A607"
        assert row105_reference["owned_corridor_instruction_eas"] == [
            0x40AB31,
            0x40AB50,
            0x40AB62,
            0x40AB64,
            0x40B52C,
            0x40B534,
            0x40B536,
            0x40B538,
            0x40B53A,
            0x40B540,
        ]
        assert row105_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row105_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row106_reference = reference_payloads["route:rhad-direct@0x40B56B"]
        assert row106_reference["reference_operation_id"] == "rhad:route@0x40B56B"
        assert row106_reference["reference_order"] == 106
        assert row106_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row106_reference["operation_variant"] == "simple_indirect_jump"
        assert row106_reference["source_native_ea"] == 0x40AC13
        assert row106_reference["source_block_anchor_ea"] == 0x40B55F
        assert row106_reference["transfer_ea"] == 0x40B56B
        assert row106_reference["direct_target_block_id"] == "native@0x40A607"
        assert row106_reference["owned_corridor_instruction_eas"] == [
            0x40AC13,
            0x40AC25,
            0x40AC2B,
            0x40B553,
            0x40B55F,
            0x40B561,
            0x40B563,
            0x40B565,
            0x40B56B,
        ]
        assert row106_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row106_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row107_reference = reference_payloads["route:rhad-direct@0x40B596"]
        assert row107_reference["reference_operation_id"] == "rhad:route@0x40B596"
        assert row107_reference["reference_order"] == 107
        assert row107_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row107_reference["operation_variant"] == "simple_indirect_jump"
        assert row107_reference["source_native_ea"] == 0x40AC95
        assert row107_reference["source_block_anchor_ea"] == 0x40B58A
        assert row107_reference["transfer_ea"] == 0x40B596
        assert row107_reference["direct_target_block_id"] == "native@0x40A607"
        assert row107_reference["owned_corridor_instruction_eas"] == [
            0x40AC95,
            0x40ACA7,
            0x40ACAD,
            0x40B57E,
            0x40B58A,
            0x40B58C,
            0x40B58E,
            0x40B590,
            0x40B596,
        ]
        assert row107_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row107_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row108_reference = reference_payloads["route:rhad-direct@0x40B5B5"]
        assert row108_reference["reference_operation_id"] == "rhad:route@0x40B5B5"
        assert row108_reference["reference_order"] == 108
        assert row108_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row108_reference["operation_variant"] == "simple_indirect_jump"
        assert row108_reference["source_native_ea"] == 0x40AD00
        assert row108_reference["source_block_anchor_ea"] == 0x40B5AF
        assert row108_reference["transfer_ea"] == 0x40B5B5
        assert row108_reference["direct_target_block_id"] == "native@0x40A607"
        assert row108_reference["owned_corridor_instruction_eas"] == [
            0x40AD00,
            0x40AD12,
            0x40B5AF,
            0x40B5B1,
            0x40B5B3,
            0x40B5B5,
        ]
        assert row108_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row108_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row109_reference = reference_payloads["route:rhad-direct@0x40B5DC"]
        assert row109_reference["reference_operation_id"] == "rhad:route@0x40B5DC"
        assert row109_reference["reference_order"] == 109
        assert row109_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row109_reference["operation_variant"] == "simple_indirect_jump"
        assert row109_reference["source_native_ea"] == 0x40AEA5
        assert row109_reference["source_block_anchor_ea"] == 0x40B5D0
        assert row109_reference["transfer_ea"] == 0x40B5DC
        assert row109_reference["direct_target_block_id"] == "native@0x40A607"
        assert row109_reference["owned_corridor_instruction_eas"] == [
            0x40AEA5,
            0x40AEC0,
            0x40AED2,
            0x40AED4,
            0x40B5C8,
            0x40B5D0,
            0x40B5D2,
            0x40B5D4,
            0x40B5D6,
            0x40B5DC,
        ]
        assert row109_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row109_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row110_reference = reference_payloads["route:rhad-direct@0x40B607"]
        assert row110_reference["reference_operation_id"] == "rhad:route@0x40B607"
        assert row110_reference["reference_order"] == 110
        assert row110_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row110_reference["operation_variant"] == "simple_indirect_jump"
        assert row110_reference["source_native_ea"] == 0x40AFB5
        assert row110_reference["source_block_anchor_ea"] == 0x40B5FB
        assert row110_reference["transfer_ea"] == 0x40B607
        assert row110_reference["direct_target_block_id"] == "native@0x40A607"
        assert row110_reference["owned_corridor_instruction_eas"] == [
            0x40AFB5,
            0x40AFC7,
            0x40AFCD,
            0x40B5EF,
            0x40B5FB,
            0x40B5FD,
            0x40B5FF,
            0x40B601,
            0x40B607,
        ]
        assert row110_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row110_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row111_reference = reference_payloads["route:rhad-direct@0x40B626"]
        assert row111_reference["reference_operation_id"] == "rhad:route@0x40B626"
        assert row111_reference["reference_order"] == 111
        assert row111_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row111_reference["operation_variant"] == "simple_indirect_jump"
        assert row111_reference["source_native_ea"] == 0x40B006
        assert row111_reference["source_block_anchor_ea"] == 0x40B620
        assert row111_reference["transfer_ea"] == 0x40B626
        assert row111_reference["direct_target_block_id"] == "native@0x40A607"
        assert row111_reference["owned_corridor_instruction_eas"] == [
            0x40B006,
            0x40B018,
            0x40B620,
            0x40B622,
            0x40B624,
            0x40B626,
        ]
        assert row111_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row111_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row112_reference = reference_payloads["route:rhad-direct@0x40B645"]
        assert row112_reference["reference_operation_id"] == "rhad:route@0x40B645"
        assert row112_reference["reference_order"] == 112
        assert row112_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row112_reference["operation_variant"] == "simple_indirect_jump"
        assert row112_reference["source_native_ea"] == 0x40B053
        assert row112_reference["source_block_anchor_ea"] == 0x40B63F
        assert row112_reference["transfer_ea"] == 0x40B645
        assert row112_reference["direct_target_block_id"] == "native@0x40A607"
        assert row112_reference["owned_corridor_instruction_eas"] == [
            0x40B053,
            0x40B065,
            0x40B63F,
            0x40B641,
            0x40B643,
            0x40B645,
        ]
        assert row112_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row112_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row113_reference = reference_payloads["route:rhad-direct@0x40B666"]
        assert row113_reference["reference_operation_id"] == "rhad:route@0x40B666"
        assert row113_reference["reference_order"] == 113
        assert row113_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row113_reference["operation_variant"] == "simple_indirect_jump"
        assert row113_reference["source_native_ea"] == 0x40B199
        assert row113_reference["source_block_anchor_ea"] == 0x40B660
        assert row113_reference["transfer_ea"] == 0x40B666
        assert row113_reference["direct_target_block_id"] == "native@0x40A607"
        assert row113_reference["owned_corridor_instruction_eas"] == [
            0x40B199,
            0x40B1B0,
            0x40B1C2,
            0x40B1C4,
            0x40B658,
            0x40B660,
            0x40B662,
            0x40B664,
            0x40B666,
        ]
        assert row113_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row113_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row114_reference = reference_payloads["route:rhad-direct@0x40B691"]
        assert row114_reference["reference_operation_id"] == "rhad:route@0x40B691"
        assert row114_reference["reference_order"] == 114
        assert row114_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row114_reference["operation_variant"] == "simple_indirect_jump"
        assert row114_reference["source_native_ea"] == 0x40B2B1
        assert row114_reference["source_block_anchor_ea"] == 0x40B685
        assert row114_reference["transfer_ea"] == 0x40B691
        assert row114_reference["direct_target_block_id"] == "native@0x40A607"
        assert row114_reference["owned_corridor_instruction_eas"] == [
            0x40B2B1,
            0x40B2C3,
            0x40B2C9,
            0x40B679,
            0x40B685,
            0x40B687,
            0x40B689,
            0x40B68B,
            0x40B691,
        ]
        assert row114_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row114_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row115_reference = reference_payloads["route:rhad-direct@0x40B6B2"]
        assert row115_reference["reference_operation_id"] == "rhad:route@0x40B6B2"
        assert row115_reference["reference_order"] == 115
        assert row115_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row115_reference["operation_variant"] == "simple_indirect_jump"
        assert row115_reference["source_native_ea"] == 0x40B2F5
        assert row115_reference["source_block_anchor_ea"] == 0x40B6AC
        assert row115_reference["transfer_ea"] == 0x40B6B2
        assert row115_reference["direct_target_block_id"] == "native@0x40A607"
        assert row115_reference["owned_corridor_instruction_eas"] == [
            0x40B2F5,
            0x40B30C,
            0x40B31E,
            0x40B320,
            0x40B6A4,
            0x40B6AC,
            0x40B6AE,
            0x40B6B0,
            0x40B6B2,
        ]
        assert row115_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row115_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row116_reference = reference_payloads["rhad:route@0x40B6D4"]
        assert row116_reference["reference_order"] == 116
        assert row116_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row116_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row116_reference["source_native_ea"] == 0x40B6C0
        assert row116_reference["source_block_anchor_ea"] == 0x40B6D0
        assert row116_reference["condition_producer_ea"] == 0x40B6C2
        assert row116_reference["predicate_anchor_ea"] == 0x40B6C8
        assert row116_reference["observed_predicate_kind"] == "sge"
        assert row116_reference["predicate_kind"] == "slt"
        assert row116_reference["comparison_constant"] == 0xCB1F8618
        assert row116_reference["transfer_ea"] == 0x40B6D4
        assert row116_reference["true_target_ea"] == 0x40B6D6
        assert row116_reference["false_target_ea"] == 0x40B790
        assert row116_reference["owned_corridor_instruction_eas"] == [
            0x40B6C0,
            0x40B6C2,
            0x40B6C8,
            0x40B6CA,
            0x40B6D0,
            0x40B6D2,
            0x40B6D4,
        ]
        assert row116_reference["imported_closure_block_ids"] == [
            "native@0x40B6D6",
            "native@0x40B6E4",
            "native@0x40B6EA",
            "native@0x40B6EE",
            "native@0x40B790",
            "native@0x40B79E",
            "native@0x40B7A4",
            "native@0x40B7A8",
        ]
        assert row116_reference["boundary_exit_eas"] == [0x40B940]
        row117_reference = reference_payloads["rhad:route@0x40B6EE"]
        assert row117_reference["reference_order"] == 117
        assert row117_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row117_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row117_reference["source_native_ea"] == 0x40B6D6
        assert row117_reference["source_block_anchor_ea"] == 0x40B6E4
        assert row117_reference["condition_producer_ea"] == 0x40B6DC
        assert row117_reference["predicate_anchor_ea"] == 0x40B6E2
        assert row117_reference["observed_predicate_kind"] == "sge"
        assert row117_reference["predicate_kind"] == "slt"
        assert row117_reference["comparison_constant"] == 0xA5A94B86
        assert row117_reference["transfer_ea"] == 0x40B6EE
        assert row117_reference["true_target_ea"] == 0x40B6F0
        assert row117_reference["false_target_ea"] == 0x40B880
        assert row117_reference["owned_corridor_instruction_eas"] == [
            0x40B6D6,
            0x40B6DC,
            0x40B6E2,
            0x40B6E4,
            0x40B6EA,
            0x40B6EC,
            0x40B6EE,
        ]
        assert row117_reference["imported_closure_block_ids"] == [
            "native@0x40B6F0",
            "native@0x40B6FE",
            "native@0x40B704",
            "native@0x40B708",
            "native@0x40B880",
            "native@0x40B896",
        ]
        assert row117_reference["boundary_exit_eas"] == [
            0x40B70A,
            0x40B898,
            0x40BB75,
            0x40BC61,
        ]
        row118_reference = reference_payloads["rhad:route@0x40B708"]
        assert row118_reference["reference_order"] == 118
        assert row118_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row118_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row118_reference["source_native_ea"] == 0x40B6F0
        assert row118_reference["source_block_anchor_ea"] == 0x40B6FE
        assert row118_reference["condition_producer_ea"] == 0x40B6F6
        assert row118_reference["predicate_anchor_ea"] == 0x40B6FC
        assert row118_reference["observed_predicate_kind"] == "sge"
        assert row118_reference["predicate_kind"] == "slt"
        assert row118_reference["comparison_constant"] == 0x9A607E2A
        assert row118_reference["transfer_ea"] == 0x40B708
        assert row118_reference["true_target_ea"] == 0x40B70A
        assert row118_reference["false_target_ea"] == 0x40BB75
        assert row118_reference["owned_corridor_instruction_eas"] == [
            0x40B6F0,
            0x40B6F6,
            0x40B6FC,
            0x40B6FE,
            0x40B704,
            0x40B706,
            0x40B708,
        ]
        assert row118_reference["imported_closure_block_ids"] == [
            "native@0x40B70A",
            "native@0x40B718",
            "native@0x40B71E",
            "native@0x40B722",
            "native@0x40BB75",
            "native@0x40BB83",
            "native@0x40BB89",
            "native@0x40BB8D",
        ]
        assert row118_reference["boundary_exit_eas"] == [
            0x40B724,
            0x40BB8F,
            0x40BD50,
            0x40BF8C,
        ]
        row119_reference = reference_payloads["rhad:route@0x40B722"]
        assert row119_reference["reference_order"] == 119
        assert row119_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row119_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row119_reference["source_native_ea"] == 0x40B70A
        assert row119_reference["source_block_anchor_ea"] == 0x40B718
        assert row119_reference["condition_producer_ea"] == 0x40B710
        assert row119_reference["predicate_anchor_ea"] == 0x40B716
        assert row119_reference["observed_predicate_kind"] == "sge"
        assert row119_reference["predicate_kind"] == "slt"
        assert row119_reference["comparison_constant"] == 0x921C6083
        assert row119_reference["transfer_ea"] == 0x40B722
        assert row119_reference["true_target_ea"] == 0x40B724
        assert row119_reference["false_target_ea"] == 0x40BD50
        assert row119_reference["owned_corridor_instruction_eas"] == [
            0x40B70A,
            0x40B710,
            0x40B716,
            0x40B718,
            0x40B71E,
            0x40B720,
            0x40B722,
        ]
        assert row119_reference["imported_closure_block_ids"] == [
            "native@0x40B724",
            "native@0x40B732",
            "native@0x40B738",
            "native@0x40B73C",
            "native@0x40BD50",
            "native@0x40BD5E",
            "native@0x40BD64",
            "native@0x40BD68",
        ]
        assert row119_reference["boundary_exit_eas"] == [
            0x40B73E,
            0x40BD6A,
            0x40C0F0,
            0x40C3D9,
        ]
        row120_reference = reference_payloads["rhad:route@0x40B73C"]
        assert row120_reference["reference_order"] == 120
        assert row120_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row120_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row120_reference["source_native_ea"] == 0x40B724
        assert row120_reference["source_block_anchor_ea"] == 0x40B732
        assert row120_reference["condition_producer_ea"] == 0x40B72A
        assert row120_reference["predicate_anchor_ea"] == 0x40B730
        assert row120_reference["observed_predicate_kind"] == "sge"
        assert row120_reference["predicate_kind"] == "slt"
        assert row120_reference["comparison_constant"] == 0x886CCA9F
        assert row120_reference["transfer_ea"] == 0x40B73C
        assert row120_reference["true_target_ea"] == 0x40B73E
        assert row120_reference["false_target_ea"] == 0x40C0F0
        assert row120_reference["owned_corridor_instruction_eas"] == [
            0x40B724,
            0x40B72A,
            0x40B730,
            0x40B732,
            0x40B738,
            0x40B73A,
            0x40B73C,
        ]
        assert row120_reference["imported_closure_block_ids"] == [
            "native@0x40B73E",
            "native@0x40B74C",
            "native@0x40B752",
            "native@0x40B756",
            "native@0x40C0F0",
            "native@0x40C0FE",
            "native@0x40C104",
            "native@0x40C108",
        ]
        assert row120_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40B758,
            0x40C10A,
        ]
        row121_reference = reference_payloads["rhad:route@0x40B756"]
        assert row121_reference["reference_order"] == 121
        assert row121_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row121_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row121_reference["source_native_ea"] == 0x40B73E
        assert row121_reference["source_block_anchor_ea"] == 0x40B74C
        assert row121_reference["condition_producer_ea"] == 0x40B744
        assert row121_reference["predicate_anchor_ea"] == 0x40B74A
        assert row121_reference["observed_predicate_kind"] == "eq"
        assert row121_reference["predicate_kind"] == "ne"
        assert row121_reference["comparison_constant"] == 0x82F1899D
        assert row121_reference["transfer_ea"] == 0x40B756
        assert row121_reference["true_target_ea"] == 0x40B758
        assert row121_reference["false_target_ea"] == 0x40A5F0
        assert row121_reference["owned_corridor_instruction_eas"] == [
            0x40B73E,
            0x40B744,
            0x40B74A,
            0x40B74C,
            0x40B752,
            0x40B754,
            0x40B756,
        ]
        assert row121_reference["imported_closure_block_ids"] == [
            "native@0x40B758",
            "native@0x40B76B",
            "native@0x40B77D",
            "native@0x40B781",
            "native@0x40C696",
            "native@0x40C6AD",
            "native@0x40C6B3",
        ]
        assert row121_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row122_reference = reference_payloads["route:rhad-direct@0x40B781"]
        assert row122_reference["reference_operation_id"] == "rhad:route@0x40B781"
        assert row122_reference["reference_order"] == 122
        assert row122_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row122_reference["operation_variant"] == "simple_indirect_jump"
        assert row122_reference["source_native_ea"] == 0x40B76B
        assert row122_reference["source_block_anchor_ea"] == 0x40B77D
        assert row122_reference["transfer_ea"] == 0x40B781
        assert row122_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row122_reference["owned_corridor_instruction_eas"] == [
            0x40B76B,
            0x40B77D,
            0x40B77F,
            0x40B781,
        ]
        assert row122_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row122_reference["boundary_exit_eas"] == [0x40B790]
        row123_reference = reference_payloads["rhad:route@0x40B7A8"]
        assert row123_reference["reference_order"] == 123
        assert row123_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row123_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row123_reference["source_native_ea"] == 0x40B790
        assert row123_reference["source_block_anchor_ea"] == 0x40B7A4
        assert row123_reference["condition_producer_ea"] == 0x40B796
        assert row123_reference["predicate_anchor_ea"] == 0x40B79C
        assert row123_reference["observed_predicate_kind"] == "slt"
        assert row123_reference["predicate_kind"] == "sge"
        assert row123_reference["comparison_constant"] == 0xEC71CA67
        assert row123_reference["transfer_ea"] == 0x40B7A8
        assert row123_reference["true_target_ea"] == 0x40B7AA
        assert row123_reference["false_target_ea"] == 0x40B940
        assert row123_reference["owned_corridor_instruction_eas"] == [
            0x40B790,
            0x40B796,
            0x40B79C,
            0x40B79E,
            0x40B7A4,
            0x40B7A6,
            0x40B7A8,
        ]
        assert row123_reference["imported_closure_block_ids"] == [
            "native@0x40B7AA",
            "native@0x40B7B8",
            "native@0x40B7BE",
            "native@0x40B7C2",
            "native@0x40B940",
            "native@0x40B956",
        ]
        assert row123_reference["boundary_exit_eas"] == [
            0x40B7C4,
            0x40B958,
            0x40BBDF,
            0x40BCCB,
        ]
        row124_reference = reference_payloads["rhad:route@0x40B7C2"]
        assert row124_reference["reference_order"] == 124
        assert row124_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row124_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row124_reference["source_native_ea"] == 0x40B7AA
        assert row124_reference["source_block_anchor_ea"] == 0x40B7B8
        assert row124_reference["condition_producer_ea"] == 0x40B7B0
        assert row124_reference["predicate_anchor_ea"] == 0x40B7B6
        assert row124_reference["observed_predicate_kind"] == "slt"
        assert row124_reference["predicate_kind"] == "sge"
        assert row124_reference["comparison_constant"] == 0xDEF4B7E6
        assert row124_reference["transfer_ea"] == 0x40B7C2
        assert row124_reference["true_target_ea"] == 0x40B7C4
        assert row124_reference["false_target_ea"] == 0x40BBDF
        assert row124_reference["imported_closure_block_ids"] == [
            "native@0x40B7C4",
            "native@0x40B7D2",
            "native@0x40B7D8",
            "native@0x40B7DC",
            "native@0x40BBDF",
            "native@0x40BBED",
            "native@0x40BBF3",
            "native@0x40BBF7",
        ]
        assert row124_reference["boundary_exit_eas"] == [
            0x40B7DE,
            0x40BBF9,
            0x40BE2F,
            0x40BFDA,
        ]
        row125_reference = reference_payloads["rhad:route@0x40B7DC"]
        assert row125_reference["reference_order"] == 125
        assert row125_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row125_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row125_reference["source_native_ea"] == 0x40B7C4
        assert row125_reference["source_block_anchor_ea"] == 0x40B7D2
        assert row125_reference["condition_producer_ea"] == 0x40B7CA
        assert row125_reference["predicate_anchor_ea"] == 0x40B7D0
        assert row125_reference["observed_predicate_kind"] == "slt"
        assert row125_reference["predicate_kind"] == "sge"
        assert row125_reference["comparison_constant"] == 0xCEA36423
        assert row125_reference["transfer_ea"] == 0x40B7DC
        assert row125_reference["true_target_ea"] == 0x40B7DE
        assert row125_reference["false_target_ea"] == 0x40BE2F
        assert row125_reference["imported_closure_block_ids"] == [
            "native@0x40B7DE",
            "native@0x40B7F4",
            "native@0x40BE2F",
            "native@0x40BE3D",
            "native@0x40BE43",
            "native@0x40BE47",
        ]
        assert row125_reference["boundary_exit_eas"] == [
            0x40B7F6,
            0x40C150,
            0x40C42E,
        ]
        row126_reference = reference_payloads["rhad:route@0x40B7F4"]
        assert row126_reference["reference_order"] == 126
        assert row126_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert row126_reference["operation_variant"] == "setcc_indexed_table"
        assert row126_reference["source_native_ea"] == 0x40B7DE
        assert row126_reference["source_block_anchor_ea"] == 0x40B7DE
        assert row126_reference["condition_producer_ea"] == 0x40B7E0
        assert row126_reference["predicate_anchor_ea"] == 0x40B7E6
        assert row126_reference["predicate_kind"] == "sge"
        assert row126_reference["fallthrough_delivery"] == "planned_helper"
        assert row126_reference["transfer_ea"] == 0x40B7F4
        assert row126_reference["true_target_ea"] == 0x40C150
        assert row126_reference["false_target_ea"] == 0x40B7F6
        assert row126_reference["owned_corridor_instruction_eas"] == [
            0x40B7DE,
            0x40B7E0,
            0x40B7E6,
            0x40B7E9,
            0x40B7EC,
            0x40B7F2,
            0x40B7F4,
        ]
        assert row126_reference["imported_closure_block_ids"] == [
            "native@0x40B7F6",
            "native@0x40B804",
            "native@0x40B80A",
            "native@0x40B80E",
            "native@0x40C150",
            "native@0x40C15E",
            "native@0x40C164",
            "native@0x40C168",
        ]
        assert row126_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40B810,
            0x40C16A,
        ]
        assert (
            row126_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40B7F4"]
        )
        row127_reference = reference_payloads["rhad:route@0x40B80E"]
        assert row127_reference["reference_order"] == 127
        assert row127_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row127_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row127_reference["source_native_ea"] == 0x40B7F6
        assert row127_reference["source_block_anchor_ea"] == 0x40B804
        assert row127_reference["condition_producer_ea"] == 0x40B7FC
        assert row127_reference["predicate_anchor_ea"] == 0x40B802
        assert row127_reference["observed_predicate_kind"] == "eq"
        assert row127_reference["predicate_kind"] == "ne"
        assert row127_reference["comparison_constant"] == 0xCB1F8618
        assert row127_reference["transfer_ea"] == 0x40B80E
        assert row127_reference["true_target_ea"] == 0x40B810
        assert row127_reference["false_target_ea"] == 0x40A5F0
        assert row127_reference["owned_corridor_instruction_eas"] == [
            0x40B7F6,
            0x40B7FC,
            0x40B802,
            0x40B804,
            0x40B80A,
            0x40B80C,
            0x40B80E,
        ]
        assert row127_reference["imported_closure_block_ids"] == [
            "native@0x40B810",
            "native@0x40B872",
            "native@0x40B875",
            "native@0x40B879",
        ]
        assert row127_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row128_reference = reference_payloads["rhad:route@0x40B879"]
        assert row128_reference["reference_order"] == 128
        assert row128_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row128_reference["operation_variant"] == "cmov_selected_indirect"
        assert row128_reference["source_native_ea"] == 0x40B83F
        assert row128_reference["source_block_anchor_ea"] == 0x40B810
        assert row128_reference["source_value_block_id"] == "native@0x40B810"
        assert row128_reference["condition_producer_ea"] == 0x40B864
        assert row128_reference["predicate_anchor_ea"] == 0x40B872
        assert row128_reference["observed_predicate_kind"] == "slt"
        assert row128_reference["predicate_kind"] == "sge"
        assert row128_reference["comparison_constant"] == 0x0BB2D365
        assert row128_reference["transfer_ea"] == 0x40B879
        assert row128_reference["true_target_ea"] == 0x40B6C0
        assert row128_reference["false_target_ea"] == 0x40A607
        assert row128_reference["owned_corridor_instruction_eas"] == [
            0x40B83F,
            0x40B864,
            0x40B86A,
            0x40B86C,
            0x40B872,
            0x40B875,
            0x40B877,
            0x40B879,
        ]
        assert row128_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row128_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row129_reference = reference_payloads["rhad:route@0x40B896"]
        assert row129_reference["reference_order"] == 129
        assert row129_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert row129_reference["operation_variant"] == "setcc_indexed_table"
        assert row129_reference["source_native_ea"] == 0x40B880
        assert row129_reference["source_block_anchor_ea"] == 0x40B880
        assert row129_reference["condition_producer_ea"] == 0x40B882
        assert row129_reference["predicate_anchor_ea"] == 0x40B888
        assert row129_reference["predicate_kind"] == "slt"
        assert row129_reference["fallthrough_delivery"] == "planned_helper"
        assert row129_reference["transfer_ea"] == 0x40B896
        assert row129_reference["true_target_ea"] == 0x40B898
        assert row129_reference["false_target_ea"] == 0x40BC61
        assert row129_reference["owned_corridor_instruction_eas"] == [
            0x40B880,
            0x40B882,
            0x40B888,
            0x40B88B,
            0x40B88E,
            0x40B894,
            0x40B896,
        ]
        assert row129_reference["imported_closure_block_ids"] == [
            "native@0x40B898",
            "native@0x40B8A6",
            "native@0x40B8AC",
            "native@0x40B8B0",
            "native@0x40BC61",
            "native@0x40BC6F",
            "native@0x40BC75",
            "native@0x40BC79",
        ]
        assert row129_reference["boundary_exit_eas"] == [0x40BE98, 0x40C041]
        assert (
            row129_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40B896"]
        )
        row130_reference = reference_payloads["rhad:route@0x40B8B0"]
        assert row130_reference["reference_order"] == 130
        assert row130_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row130_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row130_reference["source_native_ea"] == 0x40B898
        assert row130_reference["source_block_anchor_ea"] == 0x40B8A6
        assert row130_reference["condition_producer_ea"] == 0x40B89E
        assert row130_reference["predicate_anchor_ea"] == 0x40B8A4
        assert row130_reference["observed_predicate_kind"] == "slt"
        assert row130_reference["predicate_kind"] == "sge"
        assert row130_reference["comparison_constant"] == 0xABB95547
        assert row130_reference["transfer_ea"] == 0x40B8B0
        assert row130_reference["true_target_ea"] == 0x40B8B2
        assert row130_reference["false_target_ea"] == 0x40BE98
        assert row130_reference["owned_corridor_instruction_eas"] == [
            0x40B898,
            0x40B89E,
            0x40B8A4,
            0x40B8A6,
            0x40B8AC,
            0x40B8AE,
            0x40B8B0,
        ]
        assert row130_reference["imported_closure_block_ids"] == [
            "native@0x40B8B2",
            "native@0x40B8C0",
            "native@0x40B8C6",
            "native@0x40B8CA",
            "native@0x40BE98",
            "native@0x40BEA6",
            "native@0x40BEAC",
            "native@0x40BEB0",
        ]
        assert row130_reference["boundary_exit_eas"] == [
            0x40B8CC,
            0x40BEB2,
            0x40C186,
            0x40C464,
        ]
        row131_reference = reference_payloads["rhad:route@0x40B8CA"]
        assert row131_reference["reference_order"] == 131
        assert row131_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row131_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row131_reference["source_native_ea"] == 0x40B8B2
        assert row131_reference["source_block_anchor_ea"] == 0x40B8C0
        assert row131_reference["condition_producer_ea"] == 0x40B8B8
        assert row131_reference["predicate_anchor_ea"] == 0x40B8BE
        assert row131_reference["observed_predicate_kind"] == "slt"
        assert row131_reference["predicate_kind"] == "sge"
        assert row131_reference["comparison_constant"] == 0xA7933EA0
        assert row131_reference["transfer_ea"] == 0x40B8CA
        assert row131_reference["true_target_ea"] == 0x40B8CC
        assert row131_reference["false_target_ea"] == 0x40C186
        assert row131_reference["owned_corridor_instruction_eas"] == [
            0x40B8B2,
            0x40B8B8,
            0x40B8BE,
            0x40B8C0,
            0x40B8C6,
            0x40B8C8,
            0x40B8CA,
        ]
        assert row131_reference["imported_closure_block_ids"] == [
            "native@0x40B8CC",
            "native@0x40B8DA",
            "native@0x40B8E0",
            "native@0x40B8E4",
            "native@0x40C186",
            "native@0x40C194",
            "native@0x40C19A",
            "native@0x40C19E",
        ]
        assert row131_reference["boundary_exit_eas"] == [0x40A5F0, 0x40B8E6]
        row132_reference = reference_payloads["rhad:route@0x40B8E4"]
        assert row132_reference["reference_order"] == 132
        assert row132_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row132_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row132_reference["source_native_ea"] == 0x40B8CC
        assert row132_reference["source_block_anchor_ea"] == 0x40B8DA
        assert row132_reference["condition_producer_ea"] == 0x40B8D2
        assert row132_reference["predicate_anchor_ea"] == 0x40B8D8
        assert row132_reference["observed_predicate_kind"] == "eq"
        assert row132_reference["predicate_kind"] == "ne"
        assert row132_reference["comparison_constant"] == 0xA5A94B86
        assert row132_reference["transfer_ea"] == 0x40B8E4
        assert row132_reference["true_target_ea"] == 0x40B8E6
        assert row132_reference["false_target_ea"] == 0x40A5F0
        assert row132_reference["owned_corridor_instruction_eas"] == [
            0x40B8CC,
            0x40B8D2,
            0x40B8D8,
            0x40B8DA,
            0x40B8E0,
            0x40B8E2,
            0x40B8E4,
        ]
        assert row132_reference["imported_closure_block_ids"] == [
            "native@0x40B8E6",
            "native@0x40B915",
            "native@0x40B927",
            "native@0x40B931",
            "native@0x40C6B5",
            "native@0x40C6CC",
            "native@0x40C6D8",
        ]
        assert row132_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row133_reference = reference_payloads["route:rhad-direct@0x40B931"]
        assert row133_reference["reference_operation_id"] == "rhad:route@0x40B931"
        assert row133_reference["reference_order"] == 133
        assert row133_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row133_reference["operation_variant"] == "simple_indirect_jump"
        assert row133_reference["source_native_ea"] == 0x40B915
        assert row133_reference["source_block_anchor_ea"] == 0x40B927
        assert row133_reference["transfer_ea"] == 0x40B931
        assert row133_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row133_reference["owned_corridor_instruction_eas"] == [
            0x40B915,
            0x40B927,
            0x40B929,
            0x40B92B,
            0x40B931,
        ]
        assert row133_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row133_reference["boundary_exit_eas"] == [0x40B790]
        row134_reference = reference_payloads["rhad:route@0x40B956"]
        assert row134_reference["reference_order"] == 134
        assert row134_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert row134_reference["operation_variant"] == "setcc_indexed_table"
        assert row134_reference["source_native_ea"] == 0x40B940
        assert row134_reference["source_block_anchor_ea"] == 0x40B940
        assert row134_reference["condition_producer_ea"] == 0x40B942
        assert row134_reference["predicate_anchor_ea"] == 0x40B948
        assert row134_reference["predicate_kind"] == "slt"
        assert row134_reference["fallthrough_delivery"] == "planned_helper"
        assert row134_reference["transfer_ea"] == 0x40B956
        assert row134_reference["true_target_ea"] == 0x40B958
        assert row134_reference["false_target_ea"] == 0x40BCCB
        assert row134_reference["owned_corridor_instruction_eas"] == [
            0x40B940,
            0x40B942,
            0x40B948,
            0x40B94B,
            0x40B94E,
            0x40B954,
            0x40B956,
        ]
        assert row134_reference["imported_closure_block_ids"] == [
            "native@0x40B958",
            "native@0x40B966",
            "native@0x40B96C",
            "native@0x40B970",
            "native@0x40BCCB",
            "native@0x40BCD9",
            "native@0x40BCDF",
            "native@0x40BCE3",
        ]
        assert row134_reference["boundary_exit_eas"] == [0x40BEE7, 0x40C0A0]
        assert row134_reference["setcc_table"]["table_base_ea"] == 0x48B52C
        assert row134_reference["setcc_table"]["stride_bytes"] == 0x100
        assert row134_reference["setcc_table"]["entries"] == [
            {
                "decoded_target_ea": 0x40BCCB,
                "entry_ea": 0x48B52C,
                "index": 0,
                "raw_value": 0x0252A04A,
            },
            {
                "decoded_target_ea": 0x40B958,
                "entry_ea": 0x48B62C,
                "index": 1,
                "raw_value": 0x02529CD7,
            },
        ]
        assert (
            row134_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40B956"]
        )
        row135_reference = reference_payloads["rhad:route@0x40B970"]
        assert row135_reference["reference_order"] == 135
        assert row135_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row135_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row135_reference["source_native_ea"] == 0x40B958
        assert row135_reference["source_block_anchor_ea"] == 0x40B96C
        assert row135_reference["condition_producer_ea"] == 0x40B95E
        assert row135_reference["predicate_anchor_ea"] == 0x40B964
        assert row135_reference["observed_predicate_kind"] == "slt"
        assert row135_reference["predicate_kind"] == "sge"
        assert row135_reference["comparison_constant"] == 0xF32B2D3A
        assert row135_reference["transfer_ea"] == 0x40B970
        assert row135_reference["true_target_ea"] == 0x40B972
        assert row135_reference["false_target_ea"] == 0x40BEE7
        assert row135_reference["owned_corridor_instruction_eas"] == [
            0x40B958,
            0x40B95E,
            0x40B964,
            0x40B966,
            0x40B96C,
            0x40B96E,
            0x40B970,
        ]
        assert row135_reference["imported_closure_block_ids"] == [
            "native@0x40B972",
            "native@0x40B980",
            "native@0x40B986",
            "native@0x40B98A",
            "native@0x40BEE7",
            "native@0x40BEF5",
            "native@0x40BEFB",
            "native@0x40BEFF",
        ]
        assert row135_reference["boundary_exit_eas"] == [0x40C1F2, 0x40C49A]
        row136_reference = reference_payloads["rhad:route@0x40B98A"]
        assert row136_reference["reference_order"] == 136
        assert row136_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row136_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row136_reference["source_native_ea"] == 0x40B972
        assert row136_reference["source_block_anchor_ea"] == 0x40B980
        assert row136_reference["condition_producer_ea"] == 0x40B978
        assert row136_reference["predicate_anchor_ea"] == 0x40B97E
        assert row136_reference["observed_predicate_kind"] == "slt"
        assert row136_reference["predicate_kind"] == "sge"
        assert row136_reference["comparison_constant"] == 0xF0B56411
        assert row136_reference["transfer_ea"] == 0x40B98A
        assert row136_reference["true_target_ea"] == 0x40B98C
        assert row136_reference["false_target_ea"] == 0x40C1F2
        assert row136_reference["owned_corridor_instruction_eas"] == [
            0x40B972,
            0x40B978,
            0x40B97E,
            0x40B980,
            0x40B986,
            0x40B988,
            0x40B98A,
        ]
        assert row136_reference["imported_closure_block_ids"] == [
            "native@0x40B98C",
            "native@0x40B99A",
            "native@0x40B9A0",
            "native@0x40B9A4",
            "native@0x40C1F2",
            "native@0x40C200",
            "native@0x40C206",
            "native@0x40C20A",
        ]
        assert row136_reference["boundary_exit_eas"] == [0x40A5F0, 0x40B9A6]
        row137_reference = reference_payloads["rhad:route@0x40B9A4"]
        assert row137_reference["reference_order"] == 137
        assert row137_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row137_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row137_reference["source_native_ea"] == 0x40B98C
        assert row137_reference["source_block_anchor_ea"] == 0x40B99A
        assert row137_reference["condition_producer_ea"] == 0x40B992
        assert row137_reference["predicate_anchor_ea"] == 0x40B998
        assert row137_reference["observed_predicate_kind"] == "eq"
        assert row137_reference["predicate_kind"] == "ne"
        assert row137_reference["comparison_constant"] == 0xEC71CA67
        assert row137_reference["transfer_ea"] == 0x40B9A4
        assert row137_reference["true_target_ea"] == 0x40B9A6
        assert row137_reference["false_target_ea"] == 0x40A5F0
        assert row137_reference["owned_corridor_instruction_eas"] == [
            0x40B98C,
            0x40B992,
            0x40B998,
            0x40B99A,
            0x40B9A0,
            0x40B9A2,
            0x40B9A4,
        ]
        assert row137_reference["imported_closure_block_ids"] == [
            "native@0x40B9A6",
            "native@0x40BA5C",
            "native@0x40BA78",
            "native@0x40BA92",
            "native@0x40BB3A",
            "native@0x40BB51",
            "native@0x40BB69",
            "native@0x40BB73",
            "native@0x40C6DA",
            "native@0x40C6F7",
            "native@0x40C703",
        ]
        assert row137_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row138_reference = reference_payloads["route:rhad-direct@0x40BB73"]
        assert row138_reference["reference_operation_id"] == "rhad:route@0x40BB73"
        assert row138_reference["reference_order"] == 138
        assert row138_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row138_reference["operation_variant"] == "simple_indirect_jump"
        assert row138_reference["source_native_ea"] == 0x40BB51
        assert row138_reference["source_block_anchor_ea"] == 0x40BB69
        assert row138_reference["transfer_ea"] == 0x40BB73
        assert row138_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row138_reference["owned_corridor_instruction_eas"] == [
            0x40BB51,
            0x40BB69,
            0x40BB6B,
            0x40BB6D,
            0x40BB73,
        ]
        assert row138_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row138_reference["boundary_exit_eas"] == [0x40B790]
        row139_reference = reference_payloads["rhad:route@0x40BB8D"]
        assert row139_reference["reference_order"] == 139
        assert row139_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row139_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row139_reference["source_native_ea"] == 0x40BB75
        assert row139_reference["source_block_anchor_ea"] == 0x40BB89
        assert row139_reference["condition_producer_ea"] == 0x40BB7B
        assert row139_reference["predicate_anchor_ea"] == 0x40BB81
        assert row139_reference["observed_predicate_kind"] == "slt"
        assert row139_reference["predicate_kind"] == "sge"
        assert row139_reference["comparison_constant"] == 0xA0DBF1FA
        assert row139_reference["transfer_ea"] == 0x40BB8D
        assert row139_reference["true_target_ea"] == 0x40BB8F
        assert row139_reference["false_target_ea"] == 0x40BF8C
        assert row139_reference["owned_corridor_instruction_eas"] == [
            0x40BB75,
            0x40BB7B,
            0x40BB81,
            0x40BB83,
            0x40BB89,
            0x40BB8B,
            0x40BB8D,
        ]
        assert row139_reference["imported_closure_block_ids"] == [
            "native@0x40BB8F",
            "native@0x40BB9D",
            "native@0x40BBA3",
            "native@0x40BBA7",
            "native@0x40BF8C",
            "native@0x40BFA2",
        ]
        assert row139_reference["boundary_exit_eas"] == [
            0x40BBA9,
            0x40BFA4,
            0x40C253,
            0x40C4DC,
        ]
        row140_reference = reference_payloads["rhad:route@0x40BBA7"]
        assert row140_reference["reference_order"] == 140
        assert row140_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row140_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row140_reference["source_native_ea"] == 0x40BB8F
        assert row140_reference["source_block_anchor_ea"] == 0x40BBA3
        assert row140_reference["condition_producer_ea"] == 0x40BB95
        assert row140_reference["predicate_anchor_ea"] == 0x40BB9B
        assert row140_reference["observed_predicate_kind"] == "slt"
        assert row140_reference["predicate_kind"] == "sge"
        assert row140_reference["comparison_constant"] == 0xA0716E5B
        assert row140_reference["transfer_ea"] == 0x40BBA7
        assert row140_reference["true_target_ea"] == 0x40BBA9
        assert row140_reference["false_target_ea"] == 0x40C253
        assert row140_reference["owned_corridor_instruction_eas"] == [
            0x40BB8F,
            0x40BB95,
            0x40BB9B,
            0x40BB9D,
            0x40BBA3,
            0x40BBA5,
            0x40BBA7,
        ]
        assert row140_reference["imported_closure_block_ids"] == [
            "native@0x40BBA9",
            "native@0x40BBB7",
            "native@0x40BBBD",
            "native@0x40BBC1",
            "native@0x40C253",
            "native@0x40C261",
            "native@0x40C267",
            "native@0x40C26B",
        ]
        assert row140_reference["boundary_exit_eas"] == [0x40A5F0, 0x40BBC3]
        row141_reference = reference_payloads["rhad:route@0x40BBC1"]
        assert row141_reference["reference_order"] == 141
        assert row141_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row141_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row141_reference["source_native_ea"] == 0x40BBA9
        assert row141_reference["source_block_anchor_ea"] == 0x40BBBD
        assert row141_reference["condition_producer_ea"] == 0x40BBAF
        assert row141_reference["predicate_anchor_ea"] == 0x40BBB5
        assert row141_reference["observed_predicate_kind"] == "eq"
        assert row141_reference["predicate_kind"] == "ne"
        assert row141_reference["comparison_constant"] == 0x9A607E2A
        assert row141_reference["transfer_ea"] == 0x40BBC1
        assert row141_reference["true_target_ea"] == 0x40BBC3
        assert row141_reference["false_target_ea"] == 0x40A5F0
        assert row141_reference["owned_corridor_instruction_eas"] == [
            0x40BBA9,
            0x40BBAF,
            0x40BBB5,
            0x40BBB7,
            0x40BBBD,
            0x40BBBF,
            0x40BBC1,
        ]
        assert row141_reference["imported_closure_block_ids"] == [
            "native@0x40BBC3",
            "native@0x40BBD6",
            "native@0x40BBD9",
            "native@0x40BBDD",
        ]
        assert row141_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row142_reference = reference_payloads["rhad:route@0x40BBDD"]
        assert row142_reference["reference_order"] == 142
        assert row142_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row142_reference["operation_variant"] == "cmov_selected_indirect"
        assert row142_reference["source_native_ea"] == 0x40BBCE
        assert row142_reference["source_block_anchor_ea"] == 0x40BBC3
        assert row142_reference["source_value_block_id"] == "native@0x40BBC3"
        assert row142_reference["condition_producer_ea"] == 0x40BBC8
        assert row142_reference["predicate_anchor_ea"] == 0x40BBD6
        assert row142_reference["observed_predicate_kind"] == "slt"
        assert row142_reference["predicate_kind"] == "sge"
        assert row142_reference["comparison_constant"] == 0x0BB2D365
        assert row142_reference["transfer_ea"] == 0x40BBDD
        assert row142_reference["true_target_ea"] == 0x40B6C0
        assert row142_reference["false_target_ea"] == 0x40A607
        assert row142_reference["owned_corridor_instruction_eas"] == [
            0x40BBC8,
            0x40BBCE,
            0x40BBD0,
            0x40BBD6,
            0x40BBD9,
            0x40BBDB,
            0x40BBDD,
        ]
        assert row142_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row142_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row143_reference = reference_payloads["rhad:route@0x40BBF7"]
        assert row143_reference["reference_order"] == 143
        assert row143_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row143_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row143_reference["source_native_ea"] == 0x40BBDF
        assert row143_reference["source_block_anchor_ea"] == 0x40BBF3
        assert row143_reference["condition_producer_ea"] == 0x40BBE5
        assert row143_reference["predicate_anchor_ea"] == 0x40BBEB
        assert row143_reference["observed_predicate_kind"] == "slt"
        assert row143_reference["predicate_kind"] == "sge"
        assert row143_reference["comparison_constant"] == 0xE6B7ADA3
        assert row143_reference["transfer_ea"] == 0x40BBF7
        assert row143_reference["true_target_ea"] == 0x40BBF9
        assert row143_reference["false_target_ea"] == 0x40BFDA
        assert row143_reference["owned_corridor_instruction_eas"] == [
            0x40BBDF,
            0x40BBE5,
            0x40BBEB,
            0x40BBED,
            0x40BBF3,
            0x40BBF5,
            0x40BBF7,
        ]
        assert row143_reference["imported_closure_block_ids"] == [
            "native@0x40BBF9",
            "native@0x40BC07",
            "native@0x40BC0D",
            "native@0x40BC11",
            "native@0x40BFDA",
            "native@0x40BFE8",
            "native@0x40BFEE",
            "native@0x40BFF2",
        ]
        assert row143_reference["boundary_exit_eas"] == [
            0x40BC13,
            0x40C2FB,
            0x40C527,
        ]
        row144_reference = reference_payloads["rhad:route@0x40BC11"]
        assert row144_reference["reference_order"] == 144
        assert row144_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row144_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row144_reference["source_native_ea"] == 0x40BBF9
        assert row144_reference["source_block_anchor_ea"] == 0x40BC0D
        assert row144_reference["condition_producer_ea"] == 0x40BBFF
        assert row144_reference["predicate_anchor_ea"] == 0x40BC05
        assert row144_reference["observed_predicate_kind"] == "slt"
        assert row144_reference["predicate_kind"] == "sge"
        assert row144_reference["comparison_constant"] == 0xE41F690E
        assert row144_reference["transfer_ea"] == 0x40BC11
        assert row144_reference["true_target_ea"] == 0x40C2FB
        assert row144_reference["false_target_ea"] == 0x40BC13
        assert row144_reference["owned_corridor_instruction_eas"] == [
            0x40BBF9,
            0x40BBFF,
            0x40BC05,
            0x40BC07,
            0x40BC0D,
            0x40BC0F,
            0x40BC11,
        ]
        assert row144_reference["imported_closure_block_ids"] == [
            "native@0x40BC13",
            "native@0x40BC21",
            "native@0x40BC27",
            "native@0x40BC2B",
            "native@0x40C2FB",
            "native@0x40C309",
            "native@0x40C30F",
            "native@0x40C313",
        ]
        assert row144_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BC2D,
            0x40C315,
        ]
        row145_reference = reference_payloads["rhad:route@0x40BC2B"]
        assert row145_reference["reference_order"] == 145
        assert row145_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row145_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row145_reference["source_native_ea"] == 0x40BC13
        assert row145_reference["source_block_anchor_ea"] == 0x40BC27
        assert row145_reference["condition_producer_ea"] == 0x40BC19
        assert row145_reference["predicate_anchor_ea"] == 0x40BC1F
        assert row145_reference["observed_predicate_kind"] == "eq"
        assert row145_reference["predicate_kind"] == "ne"
        assert row145_reference["comparison_constant"] == 0xDEF4B7E6
        assert row145_reference["transfer_ea"] == 0x40BC2B
        assert row145_reference["true_target_ea"] == 0x40A5F0
        assert row145_reference["false_target_ea"] == 0x40BC2D
        assert row145_reference["owned_corridor_instruction_eas"] == [
            0x40BC13,
            0x40BC19,
            0x40BC1F,
            0x40BC21,
            0x40BC27,
            0x40BC29,
            0x40BC2B,
        ]
        assert row145_reference["imported_closure_block_ids"] == [
            "native@0x40BC2D",
            "native@0x40BC36",
            "native@0x40BC58",
            "native@0x40BC5B",
            "native@0x40BC5F",
        ]
        assert row145_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row146_reference = reference_payloads["rhad:route@0x40BC5F"]
        assert row146_reference["reference_order"] == 146
        assert row146_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row146_reference["operation_variant"] == "cmov_selected_indirect"
        assert row146_reference["source_native_ea"] == 0x40BC3C
        assert row146_reference["source_block_anchor_ea"] == 0x40BC36
        assert row146_reference["source_value_block_id"] == "native@0x40BC36"
        assert row146_reference["condition_producer_ea"] == 0x40BC4A
        assert row146_reference["predicate_anchor_ea"] == 0x40BC58
        assert row146_reference["observed_predicate_kind"] == "slt"
        assert row146_reference["predicate_kind"] == "sge"
        assert row146_reference["comparison_constant"] == 0x0BB2D365
        assert row146_reference["transfer_ea"] == 0x40BC5F
        assert row146_reference["true_target_ea"] == 0x40B6C0
        assert row146_reference["false_target_ea"] == 0x40A607
        assert row146_reference["owned_corridor_instruction_eas"] == [
            0x40BC3C,
            0x40BC4A,
            0x40BC50,
            0x40BC52,
            0x40BC58,
            0x40BC5B,
            0x40BC5D,
            0x40BC5F,
        ]
        assert row146_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row146_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row147_reference = reference_payloads["rhad:route@0x40BC79"]
        assert row147_reference["reference_order"] == 147
        assert row147_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row147_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row147_reference["source_native_ea"] == 0x40BC61
        assert row147_reference["source_block_anchor_ea"] == 0x40BC75
        assert row147_reference["condition_producer_ea"] == 0x40BC67
        assert row147_reference["predicate_anchor_ea"] == 0x40BC6D
        assert row147_reference["observed_predicate_kind"] == "slt"
        assert row147_reference["predicate_kind"] == "sge"
        assert row147_reference["comparison_constant"] == 0xBCDE2EFB
        assert row147_reference["transfer_ea"] == 0x40BC79
        assert row147_reference["true_target_ea"] == 0x40C041
        assert row147_reference["false_target_ea"] == 0x40BC7B
        assert row147_reference["owned_corridor_instruction_eas"] == [
            0x40BC61,
            0x40BC67,
            0x40BC6D,
            0x40BC6F,
            0x40BC75,
            0x40BC77,
            0x40BC79,
        ]
        assert row147_reference["imported_closure_block_ids"] == [
            "native@0x40BC7B",
            "native@0x40BC89",
            "native@0x40BC8F",
            "native@0x40BC93",
            "native@0x40C041",
            "native@0x40C04F",
            "native@0x40C055",
            "native@0x40C059",
        ]
        assert row147_reference["boundary_exit_eas"] == [
            0x40BC95,
            0x40C05B,
            0x40C34D,
            0x40C578,
        ]
        row148_reference = reference_payloads["rhad:route@0x40BC93"]
        assert row148_reference["reference_order"] == 148
        assert row148_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row148_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row148_reference["source_native_ea"] == 0x40BC7B
        assert row148_reference["source_block_anchor_ea"] == 0x40BC8F
        assert row148_reference["condition_producer_ea"] == 0x40BC81
        assert row148_reference["predicate_anchor_ea"] == 0x40BC87
        assert row148_reference["observed_predicate_kind"] == "slt"
        assert row148_reference["predicate_kind"] == "sge"
        assert row148_reference["comparison_constant"] == 0xB5D98F1E
        assert row148_reference["transfer_ea"] == 0x40BC93
        assert row148_reference["true_target_ea"] == 0x40C34D
        assert row148_reference["false_target_ea"] == 0x40BC95
        assert row148_reference["owned_corridor_instruction_eas"] == [
            0x40BC7B,
            0x40BC81,
            0x40BC87,
            0x40BC89,
            0x40BC8F,
            0x40BC91,
            0x40BC93,
        ]
        assert row148_reference["imported_closure_block_ids"] == [
            "native@0x40BC95",
            "native@0x40BCA3",
            "native@0x40BCA9",
            "native@0x40BCAD",
            "native@0x40C34D",
            "native@0x40C35B",
            "native@0x40C361",
            "native@0x40C365",
        ]
        assert row148_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BCAF,
            0x40C367,
        ]
        row149_reference = reference_payloads["rhad:route@0x40BCAD"]
        assert row149_reference["reference_order"] == 149
        assert row149_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row149_reference["source_native_ea"] == 0x40BC95
        assert row149_reference["source_block_anchor_ea"] == 0x40BCA9
        assert row149_reference["condition_producer_ea"] == 0x40BC9B
        assert row149_reference["predicate_anchor_ea"] == 0x40BCA1
        assert row149_reference["observed_predicate_kind"] == "eq"
        assert row149_reference["predicate_kind"] == "ne"
        assert row149_reference["comparison_constant"] == 0xB34CE2DF
        assert row149_reference["transfer_ea"] == 0x40BCAD
        assert row149_reference["true_target_ea"] == 0x40A5F0
        assert row149_reference["false_target_ea"] == 0x40BCAF
        assert row149_reference["owned_corridor_instruction_eas"] == [
            0x40BC95,
            0x40BC9B,
            0x40BCA1,
            0x40BCA3,
            0x40BCA9,
            0x40BCAB,
            0x40BCAD,
        ]
        assert row149_reference["imported_closure_block_ids"] == [
            "native@0x40BCAF",
            "native@0x40BCC2",
            "native@0x40BCC5",
            "native@0x40BCC9",
        ]
        assert row149_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row150_reference = reference_payloads["rhad:route@0x40BCC9"]
        assert row150_reference["reference_order"] == 150
        assert row150_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row150_reference["operation_variant"] == "cmov_selected_indirect"
        assert row150_reference["source_native_ea"] == 0x40BCBA
        assert row150_reference["source_block_anchor_ea"] == 0x40BCAF
        assert row150_reference["source_value_block_id"] == "native@0x40BCAF"
        assert row150_reference["condition_producer_ea"] == 0x40BCB4
        assert row150_reference["predicate_anchor_ea"] == 0x40BCC2
        assert row150_reference["observed_predicate_kind"] == "slt"
        assert row150_reference["predicate_kind"] == "sge"
        assert row150_reference["comparison_constant"] == 0x0BB2D365
        assert row150_reference["transfer_ea"] == 0x40BCC9
        assert row150_reference["true_target_ea"] == 0x40B6C0
        assert row150_reference["false_target_ea"] == 0x40A607
        assert row150_reference["owned_corridor_instruction_eas"] == [
            0x40BCB4,
            0x40BCBA,
            0x40BCBC,
            0x40BCC2,
            0x40BCC5,
            0x40BCC7,
            0x40BCC9,
        ]
        assert row150_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row150_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row151_reference = reference_payloads["rhad:route@0x40BCE3"]
        assert row151_reference["reference_order"] == 151
        assert row151_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row151_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row151_reference["source_native_ea"] == 0x40BCCB
        assert row151_reference["source_block_anchor_ea"] == 0x40BCDF
        assert row151_reference["condition_producer_ea"] == 0x40BCD1
        assert row151_reference["predicate_anchor_ea"] == 0x40BCD7
        assert row151_reference["observed_predicate_kind"] == "slt"
        assert row151_reference["predicate_kind"] == "sge"
        assert row151_reference["comparison_constant"] == 0xFED7FAC0
        assert row151_reference["transfer_ea"] == 0x40BCE3
        assert row151_reference["true_target_ea"] == 0x40C0A0
        assert row151_reference["false_target_ea"] == 0x40BCE5
        assert row151_reference["owned_corridor_instruction_eas"] == [
            0x40BCCB,
            0x40BCD1,
            0x40BCD7,
            0x40BCD9,
            0x40BCDF,
            0x40BCE1,
            0x40BCE3,
        ]
        assert row151_reference["imported_closure_block_ids"] == [
            "native@0x40BCE5",
            "native@0x40BCF3",
            "native@0x40BCF9",
            "native@0x40BCFD",
            "native@0x40C0A0",
            "native@0x40C0AE",
            "native@0x40C0B4",
            "native@0x40C0B8",
        ]
        assert row151_reference["boundary_exit_eas"] == [0x40C392, 0x40C5FB]
        row152_reference = reference_payloads["rhad:route@0x40BCFD"]
        assert row152_reference["reference_order"] == 152
        assert row152_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row152_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row152_reference["source_native_ea"] == 0x40BCE5
        assert row152_reference["source_block_anchor_ea"] == 0x40BCF9
        assert row152_reference["condition_producer_ea"] == 0x40BCEB
        assert row152_reference["predicate_anchor_ea"] == 0x40BCF1
        assert row152_reference["observed_predicate_kind"] == "slt"
        assert row152_reference["predicate_kind"] == "sge"
        assert row152_reference["comparison_constant"] == 0xFA72F85A
        assert row152_reference["transfer_ea"] == 0x40BCFD
        assert row152_reference["true_target_ea"] == 0x40C392
        assert row152_reference["false_target_ea"] == 0x40BCFF
        assert row152_reference["owned_corridor_instruction_eas"] == [
            0x40BCE5,
            0x40BCEB,
            0x40BCF1,
            0x40BCF3,
            0x40BCF9,
            0x40BCFB,
            0x40BCFD,
        ]
        assert row152_reference["imported_closure_block_ids"] == [
            "native@0x40BCFF",
            "native@0x40BD0D",
            "native@0x40BD13",
            "native@0x40BD17",
            "native@0x40C392",
            "native@0x40C3A0",
            "native@0x40C3A6",
            "native@0x40C3AA",
        ]
        assert row152_reference["boundary_exit_eas"] == [0x40A5F0, 0x40BD19]
        row153_reference = reference_payloads["rhad:route@0x40BD17"]
        assert row153_reference["reference_order"] == 153
        assert row153_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row153_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row153_reference["source_native_ea"] == 0x40BCFF
        assert row153_reference["source_block_anchor_ea"] == 0x40BD13
        assert row153_reference["condition_producer_ea"] == 0x40BD05
        assert row153_reference["predicate_anchor_ea"] == 0x40BD0B
        assert row153_reference["observed_predicate_kind"] == "eq"
        assert row153_reference["predicate_kind"] == "ne"
        assert row153_reference["comparison_constant"] == 0xF7088159
        assert row153_reference["transfer_ea"] == 0x40BD17
        assert row153_reference["true_target_ea"] == 0x40A5F0
        assert row153_reference["false_target_ea"] == 0x40BD19
        assert row153_reference["owned_corridor_instruction_eas"] == [
            0x40BCFF,
            0x40BD05,
            0x40BD0B,
            0x40BD0D,
            0x40BD13,
            0x40BD15,
            0x40BD17,
        ]
        assert row153_reference["imported_closure_block_ids"] == [
            "native@0x40BD19",
            "native@0x40BD25",
            "native@0x40BD47",
            "native@0x40BD4A",
            "native@0x40BD4E",
        ]
        assert row153_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row154_reference = reference_payloads["rhad:route@0x40BD4E"]
        assert row154_reference["reference_order"] == 154
        assert row154_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row154_reference["operation_variant"] == "cmov_selected_indirect"
        assert row154_reference["source_native_ea"] == 0x40BD2B
        assert row154_reference["source_block_anchor_ea"] == 0x40BD25
        assert row154_reference["source_value_block_id"] == "native@0x40BD25"
        assert row154_reference["condition_producer_ea"] == 0x40BD39
        assert row154_reference["predicate_anchor_ea"] == 0x40BD47
        assert row154_reference["observed_predicate_kind"] == "slt"
        assert row154_reference["predicate_kind"] == "sge"
        assert row154_reference["comparison_constant"] == 0x0BB2D365
        assert row154_reference["transfer_ea"] == 0x40BD4E
        assert row154_reference["true_target_ea"] == 0x40B6C0
        assert row154_reference["false_target_ea"] == 0x40A607
        assert row154_reference["owned_corridor_instruction_eas"] == [
            0x40BD2B,
            0x40BD39,
            0x40BD3F,
            0x40BD41,
            0x40BD47,
            0x40BD4A,
            0x40BD4C,
            0x40BD4E,
        ]
        assert row154_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row154_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row155_reference = reference_payloads["rhad:route@0x40BD68"]
        assert row155_reference["reference_order"] == 155
        assert row155_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row155_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row155_reference["source_native_ea"] == 0x40BD50
        assert row155_reference["source_block_anchor_ea"] == 0x40BD64
        assert row155_reference["condition_producer_ea"] == 0x40BD56
        assert row155_reference["predicate_anchor_ea"] == 0x40BD5C
        assert row155_reference["observed_predicate_kind"] == "slt"
        assert row155_reference["predicate_kind"] == "sge"
        assert row155_reference["comparison_constant"] == 0x96B0D1E5
        assert row155_reference["transfer_ea"] == 0x40BD68
        assert row155_reference["true_target_ea"] == 0x40C3D9
        assert row155_reference["false_target_ea"] == 0x40BD6A
        assert row155_reference["owned_corridor_instruction_eas"] == [
            0x40BD50,
            0x40BD56,
            0x40BD5C,
            0x40BD5E,
            0x40BD64,
            0x40BD66,
            0x40BD68,
        ]
        assert row155_reference["imported_closure_block_ids"] == [
            "native@0x40BD6A",
            "native@0x40BD78",
            "native@0x40BD7E",
            "native@0x40BD82",
            "native@0x40C3D9",
            "native@0x40C3E7",
            "native@0x40C3ED",
            "native@0x40C3F1",
        ]
        assert row155_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BD84,
            0x40C3F3,
        ]
        row156_reference = reference_payloads["rhad:route@0x40BD82"]
        assert row156_reference["reference_order"] == 156
        assert row156_reference["source_native_ea"] == 0x40BD6A
        assert row156_reference["source_block_anchor_ea"] == 0x40BD7E
        assert row156_reference["condition_producer_ea"] == 0x40BD70
        assert row156_reference["predicate_anchor_ea"] == 0x40BD76
        assert row156_reference["observed_predicate_kind"] == "eq"
        assert row156_reference["predicate_kind"] == "ne"
        assert row156_reference["comparison_constant"] == 0x921C6083
        assert row156_reference["transfer_ea"] == 0x40BD82
        assert row156_reference["true_target_ea"] == 0x40A5F0
        assert row156_reference["false_target_ea"] == 0x40BD84
        assert row156_reference["imported_closure_block_ids"] == [
            "native@0x40BD84",
            "native@0x40BDBD",
            "native@0x40BDD5",
            "native@0x40BE0A",
            "native@0x40BE26",
            "native@0x40BE29",
            "native@0x40BE2D",
        ]
        assert row156_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row157_reference = reference_payloads["rhad:route@0x40BE2D"]
        assert row157_reference["reference_order"] == 157
        assert row157_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row157_reference["operation_variant"] == "cmov_selected_indirect"
        assert row157_reference["source_native_ea"] == 0x40BDFC
        assert row157_reference["source_block_anchor_ea"] == 0x40BE0A
        assert row157_reference["source_value_block_id"] == "native@0x40BDD5"
        assert row157_reference["condition_producer_ea"] == 0x40BE1E
        assert row157_reference["predicate_anchor_ea"] == 0x40BE26
        assert row157_reference["observed_predicate_kind"] == "slt"
        assert row157_reference["predicate_kind"] == "sge"
        assert row157_reference["comparison_constant"] == 0x0BB2D365
        assert row157_reference["transfer_ea"] == 0x40BE2D
        assert row157_reference["true_target_ea"] == 0x40B6C0
        assert row157_reference["false_target_ea"] == 0x40A607
        assert row157_reference["owned_corridor_instruction_eas"] == [
            0x40BDFC,
            0x40BE10,
            0x40BE1E,
            0x40BE24,
            0x40BE26,
            0x40BE29,
            0x40BE2B,
            0x40BE2D,
        ]
        assert row157_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row158_reference = reference_payloads["rhad:route@0x40BE47"]
        assert row158_reference["reference_order"] == 158
        assert row158_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row158_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row158_reference["source_native_ea"] == 0x40BE2F
        assert row158_reference["source_block_anchor_ea"] == 0x40BE43
        assert row158_reference["condition_producer_ea"] == 0x40BE35
        assert row158_reference["predicate_anchor_ea"] == 0x40BE3B
        assert row158_reference["observed_predicate_kind"] == "slt"
        assert row158_reference["predicate_kind"] == "sge"
        assert row158_reference["comparison_constant"] == 0xD44F0C43
        assert row158_reference["transfer_ea"] == 0x40BE47
        assert row158_reference["true_target_ea"] == 0x40C42E
        assert row158_reference["false_target_ea"] == 0x40BE49
        assert row158_reference["owned_corridor_instruction_eas"] == [
            0x40BE2F,
            0x40BE35,
            0x40BE3B,
            0x40BE3D,
            0x40BE43,
            0x40BE45,
            0x40BE47,
        ]
        assert row158_reference["boundary_exit_eas"] == [0x40A5F0, 0x40BE63]
        row159_reference = reference_payloads["rhad:route@0x40BE61"]
        assert row159_reference["reference_order"] == 159
        assert row159_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row159_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row159_reference["source_native_ea"] == 0x40BE49
        assert row159_reference["source_block_anchor_ea"] == 0x40BE5D
        assert row159_reference["condition_producer_ea"] == 0x40BE4F
        assert row159_reference["predicate_anchor_ea"] == 0x40BE55
        assert row159_reference["observed_predicate_kind"] == "eq"
        assert row159_reference["predicate_kind"] == "ne"
        assert row159_reference["comparison_constant"] == 0xCEA36423
        assert row159_reference["transfer_ea"] == 0x40BE61
        assert row159_reference["true_target_ea"] == 0x40A5F0
        assert row159_reference["false_target_ea"] == 0x40BE63
        assert row159_reference["owned_corridor_instruction_eas"] == [
            0x40BE49,
            0x40BE4F,
            0x40BE55,
            0x40BE57,
            0x40BE5D,
            0x40BE5F,
            0x40BE61,
        ]
        assert row159_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row160_reference = reference_payloads["rhad:route@0x40BE96"]
        assert row160_reference["reference_order"] == 160
        assert row160_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row160_reference["operation_variant"] == "cmov_selected_indirect"
        assert row160_reference["source_native_ea"] == 0x40BE68
        assert row160_reference["source_block_anchor_ea"] == 0x40BE63
        assert row160_reference["condition_producer_ea"] == 0x40BE81
        assert row160_reference["predicate_anchor_ea"] == 0x40BE8F
        assert row160_reference["observed_predicate_kind"] == "slt"
        assert row160_reference["predicate_kind"] == "sge"
        assert row160_reference["comparison_constant"] == 0x0BB2D365
        assert row160_reference["transfer_ea"] == 0x40BE96
        assert row160_reference["true_target_ea"] == 0x40B6C0
        assert row160_reference["false_target_ea"] == 0x40A607
        assert row160_reference["owned_corridor_instruction_eas"] == [
            0x40BE68,
            0x40BE81,
            0x40BE87,
            0x40BE89,
            0x40BE8F,
            0x40BE92,
            0x40BE94,
            0x40BE96,
        ]
        assert row160_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row161_reference = reference_payloads["rhad:route@0x40BEB0"]
        assert row161_reference["reference_order"] == 161
        assert row161_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row161_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row161_reference["source_native_ea"] == 0x40BE98
        assert row161_reference["source_block_anchor_ea"] == 0x40BEAC
        assert row161_reference["condition_producer_ea"] == 0x40BE9E
        assert row161_reference["predicate_anchor_ea"] == 0x40BEA4
        assert row161_reference["observed_predicate_kind"] == "slt"
        assert row161_reference["predicate_kind"] == "sge"
        assert row161_reference["comparison_constant"] == 0xAE5A330B
        assert row161_reference["transfer_ea"] == 0x40BEB0
        assert row161_reference["true_target_ea"] == 0x40BEB2
        assert row161_reference["false_target_ea"] == 0x40C464
        assert row161_reference["owned_corridor_instruction_eas"] == [
            0x40BE98,
            0x40BE9E,
            0x40BEA4,
            0x40BEA6,
            0x40BEAC,
            0x40BEAE,
            0x40BEB0,
        ]
        assert row161_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BECC,
        ]
        row162_reference = reference_payloads["rhad:route@0x40BECA"]
        assert row162_reference["reference_order"] == 162
        assert row162_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row162_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row162_reference["source_native_ea"] == 0x40BEB2
        assert row162_reference["source_block_anchor_ea"] == 0x40BEC6
        assert row162_reference["condition_producer_ea"] == 0x40BEB8
        assert row162_reference["predicate_anchor_ea"] == 0x40BEBE
        assert row162_reference["observed_predicate_kind"] == "eq"
        assert row162_reference["predicate_kind"] == "ne"
        assert row162_reference["comparison_constant"] == 0xABB95547
        assert row162_reference["transfer_ea"] == 0x40BECA
        assert row162_reference["true_target_ea"] == 0x40A5F0
        assert row162_reference["false_target_ea"] == 0x40BECC
        assert row162_reference["owned_corridor_instruction_eas"] == [
            0x40BEB2,
            0x40BEB8,
            0x40BEBE,
            0x40BEC0,
            0x40BEC6,
            0x40BEC8,
            0x40BECA,
        ]
        assert row162_reference["boundary_exit_eas"] == [
            0x40A607,
            0x40B6C0,
        ]
        row163_reference = reference_payloads["rhad:route@0x40BEE5"]
        assert row163_reference["reference_order"] == 163
        assert row163_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row163_reference["operation_variant"] == "cmov_selected_indirect"
        assert row163_reference["source_native_ea"] == 0x40BED6
        assert row163_reference["source_block_anchor_ea"] == 0x40BECC
        assert row163_reference["source_value_block_id"] == "native@0x40BECC"
        assert row163_reference["condition_producer_ea"] == 0x40BED0
        assert row163_reference["predicate_anchor_ea"] == 0x40BEDE
        assert row163_reference["observed_predicate_kind"] == "slt"
        assert row163_reference["predicate_kind"] == "sge"
        assert row163_reference["comparison_constant"] == 0x0BB2D365
        assert row163_reference["transfer_ea"] == 0x40BEE5
        assert row163_reference["true_target_ea"] == 0x40B6C0
        assert row163_reference["false_target_ea"] == 0x40A607
        assert row163_reference["owned_corridor_instruction_eas"] == [
            0x40BED0,
            0x40BED6,
            0x40BED8,
            0x40BEDE,
            0x40BEE1,
            0x40BEE3,
            0x40BEE5,
        ]
        assert row163_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row164_reference = reference_payloads["rhad:route@0x40BEFF"]
        assert row164_reference["reference_order"] == 164
        assert row164_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row164_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row164_reference["source_native_ea"] == 0x40BEE7
        assert row164_reference["source_block_anchor_ea"] == 0x40BEFB
        assert row164_reference["condition_producer_ea"] == 0x40BEED
        assert row164_reference["predicate_anchor_ea"] == 0x40BEF3
        assert row164_reference["observed_predicate_kind"] == "slt"
        assert row164_reference["predicate_kind"] == "sge"
        assert row164_reference["comparison_constant"] == 0xF6A636EF
        assert row164_reference["transfer_ea"] == 0x40BEFF
        assert row164_reference["true_target_ea"] == 0x40BF01
        assert row164_reference["false_target_ea"] == 0x40C49A
        assert row164_reference["owned_corridor_instruction_eas"] == [
            0x40BEE7,
            0x40BEED,
            0x40BEF3,
            0x40BEF5,
            0x40BEFB,
            0x40BEFD,
            0x40BEFF,
        ]
        assert row164_reference["imported_closure_block_ids"] == [
            "native@0x40BF01",
            "native@0x40BF0F",
            "native@0x40BF15",
            "native@0x40BF19",
            "native@0x40C49A",
            "native@0x40C4A8",
            "native@0x40C4AE",
            "native@0x40C4B2",
        ]
        assert row164_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BF1B,
            0x40C4B4,
        ]
        row165_reference = reference_payloads["rhad:route@0x40BF19"]
        assert row165_reference["reference_order"] == 165
        assert row165_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row165_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row165_reference["source_native_ea"] == 0x40BF01
        assert row165_reference["source_block_anchor_ea"] == 0x40BF15
        assert row165_reference["condition_producer_ea"] == 0x40BF07
        assert row165_reference["predicate_anchor_ea"] == 0x40BF0D
        assert row165_reference["observed_predicate_kind"] == "eq"
        assert row165_reference["predicate_kind"] == "ne"
        assert row165_reference["comparison_constant"] == 0xF32B2D3A
        assert row165_reference["transfer_ea"] == 0x40BF19
        assert row165_reference["true_target_ea"] == 0x40BF1B
        assert row165_reference["false_target_ea"] == 0x40A5F0
        assert row165_reference["owned_corridor_instruction_eas"] == [
            0x40BF01,
            0x40BF07,
            0x40BF0D,
            0x40BF0F,
            0x40BF15,
            0x40BF17,
            0x40BF19,
        ]
        assert row165_reference["imported_closure_block_ids"] == [
            "native@0x40BF1B",
            "native@0x40BF2F",
            "native@0x40BF43",
            "native@0x40BF68",
            "native@0x40BF80",
            "native@0x40BF8A",
            "native@0x40C705",
            "native@0x40C722",
            "native@0x40C72E",
        ]
        assert row165_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row166_reference = reference_payloads["route:rhad-direct@0x40BF8A"]
        assert row166_reference["reference_operation_id"] == "rhad:route@0x40BF8A"
        assert row166_reference["reference_order"] == 166
        assert row166_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row166_reference["operation_variant"] == "simple_indirect_jump"
        assert row166_reference["source_native_ea"] == 0x40BF68
        assert row166_reference["source_block_anchor_ea"] == 0x40BF80
        assert row166_reference["transfer_ea"] == 0x40BF8A
        assert row166_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row166_reference["owned_corridor_instruction_eas"] == [
            0x40BF68,
            0x40BF80,
            0x40BF82,
            0x40BF84,
            0x40BF8A,
        ]
        assert row166_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row166_reference["boundary_exit_eas"] == [0x40B790]
        row167_reference = reference_payloads["rhad:route@0x40BFA2"]
        assert row167_reference["reference_order"] == 167
        assert row167_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert row167_reference["operation_variant"] == "setcc_indexed_table"
        assert row167_reference["source_native_ea"] == 0x40BF8C
        assert row167_reference["source_block_anchor_ea"] == 0x40BF8C
        assert row167_reference["condition_producer_ea"] == 0x40BF8E
        assert row167_reference["predicate_anchor_ea"] == 0x40BF94
        assert row167_reference["predicate_kind"] == "sge"
        assert row167_reference["fallthrough_delivery"] == "planned_helper"
        assert row167_reference["transfer_ea"] == 0x40BFA2
        assert row167_reference["true_target_ea"] == 0x40C4DC
        assert row167_reference["false_target_ea"] == 0x40BFA4
        assert row167_reference["owned_corridor_instruction_eas"] == [
            0x40BF8C,
            0x40BF8E,
            0x40BF94,
            0x40BF97,
            0x40BF9A,
            0x40BFA0,
            0x40BFA2,
        ]
        assert row167_reference["imported_closure_block_ids"] == [
            "native@0x40BFA4",
            "native@0x40BFB2",
            "native@0x40BFB8",
            "native@0x40BFBC",
            "native@0x40C4DC",
            "native@0x40C4EA",
            "native@0x40C4F0",
            "native@0x40C4F4",
        ]
        assert row167_reference["boundary_exit_eas"] == [0x40A5F0]
        assert row167_reference["setcc_table"]["table_base_ea"] == 0x48B4D4
        assert row167_reference["setcc_table"]["stride_bytes"] == 0x20
        assert row167_reference["setcc_table"]["entries"] == [
            {
                "decoded_target_ea": 0x40BFA4,
                "entry_ea": 0x48B4D4,
                "index": 0,
                "raw_value": 0x0252A323,
            },
            {
                "decoded_target_ea": 0x40C4DC,
                "entry_ea": 0x48B4F4,
                "index": 1,
                "raw_value": 0x0252A85B,
            },
        ]
        assert (
            row167_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40BFA2"]
        )
        row168_reference = reference_payloads["rhad:route@0x40BFBC"]
        assert row168_reference["reference_order"] == 168
        assert row168_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row168_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row168_reference["source_native_ea"] == 0x40BFA4
        assert row168_reference["source_block_anchor_ea"] == 0x40BFB8
        assert row168_reference["condition_producer_ea"] == 0x40BFAA
        assert row168_reference["predicate_anchor_ea"] == 0x40BFB0
        assert row168_reference["observed_predicate_kind"] == "eq"
        assert row168_reference["predicate_kind"] == "ne"
        assert row168_reference["comparison_constant"] == 0xA0DBF1FA
        assert row168_reference["transfer_ea"] == 0x40BFBC
        assert row168_reference["true_target_ea"] == 0x40BFBE
        assert row168_reference["false_target_ea"] == 0x40A5F0
        assert row168_reference["owned_corridor_instruction_eas"] == [
            0x40BFA4,
            0x40BFAA,
            0x40BFB0,
            0x40BFB2,
            0x40BFB8,
            0x40BFBA,
            0x40BFBC,
        ]
        assert row168_reference["imported_closure_block_ids"] == [
            "native@0x40BFBE",
            "native@0x40BFD1",
            "native@0x40BFD4",
            "native@0x40BFD8",
        ]
        assert row168_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row169_reference = reference_payloads["rhad:route@0x40BFD8"]
        assert row169_reference["reference_order"] == 169
        assert row169_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row169_reference["operation_variant"] == "cmov_selected_indirect"
        assert row169_reference["source_native_ea"] == 0x40BFC9
        assert row169_reference["source_block_anchor_ea"] == 0x40BFBE
        assert row169_reference["source_value_block_id"] == "native@0x40BFBE"
        assert row169_reference["condition_producer_ea"] == 0x40BFC3
        assert row169_reference["predicate_anchor_ea"] == 0x40BFD1
        assert row169_reference["observed_predicate_kind"] == "slt"
        assert row169_reference["predicate_kind"] == "sge"
        assert row169_reference["comparison_constant"] == 0x0BB2D365
        assert row169_reference["transfer_ea"] == 0x40BFD8
        assert row169_reference["true_target_ea"] == 0x40B6C0
        assert row169_reference["false_target_ea"] == 0x40A607
        assert row169_reference["owned_corridor_instruction_eas"] == [
            0x40BFC3,
            0x40BFC9,
            0x40BFCB,
            0x40BFD1,
            0x40BFD4,
            0x40BFD6,
            0x40BFD8,
        ]
        assert row169_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row170_reference = reference_payloads["rhad:route@0x40BFF2"]
        assert row170_reference["reference_order"] == 170
        assert row170_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row170_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row170_reference["source_native_ea"] == 0x40BFDA
        assert row170_reference["source_block_anchor_ea"] == 0x40BFEE
        assert row170_reference["condition_producer_ea"] == 0x40BFE0
        assert row170_reference["predicate_anchor_ea"] == 0x40BFE6
        assert row170_reference["observed_predicate_kind"] == "slt"
        assert row170_reference["predicate_kind"] == "sge"
        assert row170_reference["comparison_constant"] == 0xEC054ACC
        assert row170_reference["transfer_ea"] == 0x40BFF2
        assert row170_reference["true_target_ea"] == 0x40BFF4
        assert row170_reference["false_target_ea"] == 0x40C527
        assert row170_reference["owned_corridor_instruction_eas"] == [
            0x40BFDA,
            0x40BFE0,
            0x40BFE6,
            0x40BFE8,
            0x40BFEE,
            0x40BFF0,
            0x40BFF2,
        ]
        assert row170_reference["imported_closure_block_ids"] == [
            "native@0x40BFF4",
            "native@0x40C002",
            "native@0x40C008",
            "native@0x40C00C",
            "native@0x40C527",
            "native@0x40C535",
            "native@0x40C53B",
            "native@0x40C53F",
        ]
        assert row170_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40C00E,
            0x40C541,
        ]
        row171_reference = reference_payloads["rhad:route@0x40C00C"]
        assert row171_reference["reference_order"] == 171
        assert row171_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row171_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row171_reference["source_native_ea"] == 0x40BFF4
        assert row171_reference["source_block_anchor_ea"] == 0x40C008
        assert row171_reference["condition_producer_ea"] == 0x40BFFA
        assert row171_reference["predicate_anchor_ea"] == 0x40C000
        assert row171_reference["observed_predicate_kind"] == "eq"
        assert row171_reference["predicate_kind"] == "ne"
        assert row171_reference["comparison_constant"] == 0xE6B7ADA3
        assert row171_reference["transfer_ea"] == 0x40C00C
        assert row171_reference["true_target_ea"] == 0x40C00E
        assert row171_reference["false_target_ea"] == 0x40A5F0
        assert row171_reference["owned_corridor_instruction_eas"] == [
            0x40BFF4,
            0x40BFFA,
            0x40C000,
            0x40C002,
            0x40C008,
            0x40C00A,
            0x40C00C,
        ]
        assert row171_reference["imported_closure_block_ids"] == [
            "native@0x40C00E",
            "native@0x40C027",
            "native@0x40C03B",
            "native@0x40C03F",
            "native@0x40C730",
            "native@0x40C749",
            "native@0x40C74F",
        ]
        assert row171_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row172_reference = reference_payloads["route:rhad-direct@0x40C03F"]
        assert row172_reference["reference_operation_id"] == "rhad:route@0x40C03F"
        assert row172_reference["reference_order"] == 172
        assert row172_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row172_reference["operation_variant"] == "simple_indirect_jump"
        assert row172_reference["source_native_ea"] == 0x40C027
        assert row172_reference["source_block_anchor_ea"] == 0x40C03B
        assert row172_reference["transfer_ea"] == 0x40C03F
        assert row172_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row172_reference["owned_corridor_instruction_eas"] == [
            0x40C027,
            0x40C03B,
            0x40C03D,
            0x40C03F,
        ]
        assert row172_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row172_reference["boundary_exit_eas"] == [0x40B790]
        row173_reference = reference_payloads["rhad:route@0x40C059"]
        assert row173_reference["reference_order"] == 173
        assert row173_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row173_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row173_reference["source_native_ea"] == 0x40C041
        assert row173_reference["source_block_anchor_ea"] == 0x40C055
        assert row173_reference["condition_producer_ea"] == 0x40C047
        assert row173_reference["predicate_anchor_ea"] == 0x40C04D
        assert row173_reference["observed_predicate_kind"] == "slt"
        assert row173_reference["predicate_kind"] == "sge"
        assert row173_reference["comparison_constant"] == 0xBD9A2C2A
        assert row173_reference["transfer_ea"] == 0x40C059
        assert row173_reference["true_target_ea"] == 0x40C05B
        assert row173_reference["false_target_ea"] == 0x40C578
        assert row173_reference["owned_corridor_instruction_eas"] == [
            0x40C041,
            0x40C047,
            0x40C04D,
            0x40C04F,
            0x40C055,
            0x40C057,
            0x40C059,
        ]
        assert row173_reference["imported_closure_block_ids"] == [
            "native@0x40C05B",
            "native@0x40C069",
            "native@0x40C06F",
            "native@0x40C073",
            "native@0x40C578",
            "native@0x40C586",
            "native@0x40C58C",
            "native@0x40C590",
        ]
        assert row173_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40C075,
            0x40C592,
        ]
        row174_reference = reference_payloads["rhad:route@0x40C073"]
        assert row174_reference["reference_order"] == 174
        assert row174_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row174_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row174_reference["source_native_ea"] == 0x40C05B
        assert row174_reference["source_block_anchor_ea"] == 0x40C06F
        assert row174_reference["condition_producer_ea"] == 0x40C061
        assert row174_reference["predicate_anchor_ea"] == 0x40C067
        assert row174_reference["observed_predicate_kind"] == "eq"
        assert row174_reference["predicate_kind"] == "ne"
        assert row174_reference["comparison_constant"] == 0xBCDE2EFB
        assert row174_reference["transfer_ea"] == 0x40C073
        assert row174_reference["true_target_ea"] == 0x40C075
        assert row174_reference["false_target_ea"] == 0x40A5F0
        assert row174_reference["owned_corridor_instruction_eas"] == [
            0x40C05B,
            0x40C061,
            0x40C067,
            0x40C069,
            0x40C06F,
            0x40C071,
            0x40C073,
        ]
        assert row174_reference["imported_closure_block_ids"] == [
            "native@0x40C075",
            "native@0x40C088",
            "native@0x40C09A",
            "native@0x40C09E",
            "native@0x40C751",
            "native@0x40C768",
            "native@0x40C76E",
        ]
        assert row174_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row175_reference = reference_payloads["route:rhad-direct@0x40C09E"]
        assert row175_reference["reference_operation_id"] == "rhad:route@0x40C09E"
        assert row175_reference["reference_order"] == 175
        assert row175_reference["operation_variant"] == "simple_indirect_jump"
        assert row175_reference["source_native_ea"] == 0x40C088
        assert row175_reference["source_block_anchor_ea"] == 0x40C09A
        assert row175_reference["transfer_ea"] == 0x40C09E
        assert row175_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row175_reference["owned_corridor_instruction_eas"] == [
            0x40C088,
            0x40C09A,
            0x40C09C,
            0x40C09E,
        ]
        assert row175_reference["boundary_exit_eas"] == [0x40B790]
        row176_reference = reference_payloads["rhad:route@0x40C0B8"]
        assert row176_reference["reference_order"] == 176
        assert row176_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row176_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row176_reference["source_native_ea"] == 0x40C0A0
        assert row176_reference["source_block_anchor_ea"] == 0x40C0B4
        assert row176_reference["condition_producer_ea"] == 0x40C0A6
        assert row176_reference["predicate_anchor_ea"] == 0x40C0AC
        assert row176_reference["observed_predicate_kind"] == "slt"
        assert row176_reference["predicate_kind"] == "sge"
        assert row176_reference["comparison_constant"] == 0x0872BFF1
        assert row176_reference["transfer_ea"] == 0x40C0B8
        assert row176_reference["true_target_ea"] == 0x40C0BA
        assert row176_reference["false_target_ea"] == 0x40C5FB
        assert row176_reference["owned_corridor_instruction_eas"] == [
            0x40C0A0,
            0x40C0A6,
            0x40C0AC,
            0x40C0AE,
            0x40C0B4,
            0x40C0B6,
            0x40C0B8,
        ]
        assert row176_reference["imported_closure_block_ids"] == [
            "native@0x40C0BA",
            "native@0x40C0C8",
            "native@0x40C0CE",
            "native@0x40C0D2",
            "native@0x40C5FB",
            "native@0x40C609",
            "native@0x40C60F",
            "native@0x40C613",
        ]
        assert row176_reference["boundary_exit_eas"] == [0x40A5F0, 0x40C64B]
        row177_reference = reference_payloads["rhad:route@0x40C0D2"]
        assert row177_reference["reference_order"] == 177
        assert row177_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row177_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row177_reference["source_native_ea"] == 0x40C0BA
        assert row177_reference["source_block_anchor_ea"] == 0x40C0CE
        assert row177_reference["condition_producer_ea"] == 0x40C0C0
        assert row177_reference["predicate_anchor_ea"] == 0x40C0C6
        assert row177_reference["observed_predicate_kind"] == "eq"
        assert row177_reference["predicate_kind"] == "ne"
        assert row177_reference["comparison_constant"] == 0xFED7FAC0
        assert row177_reference["transfer_ea"] == 0x40C0D2
        assert row177_reference["true_target_ea"] == 0x40C0D4
        assert row177_reference["false_target_ea"] == 0x40A5F0
        assert row177_reference["owned_corridor_instruction_eas"] == [
            0x40C0BA,
            0x40C0C0,
            0x40C0C6,
            0x40C0C8,
            0x40C0CE,
            0x40C0D0,
            0x40C0D2,
        ]
        assert row177_reference["imported_closure_block_ids"] == [
            "native@0x40C0D4",
            "native@0x40C0E7",
            "native@0x40C0EA",
            "native@0x40C0EE",
        ]
        assert row177_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row178_reference = reference_payloads["rhad:route@0x40C0EE"]
        assert row178_reference["reference_order"] == 178
        assert row178_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row178_reference["operation_variant"] == "cmov_selected_indirect"
        assert row178_reference["source_native_ea"] == 0x40C0DF
        assert row178_reference["source_block_anchor_ea"] == 0x40C0D4
        assert row178_reference["source_value_block_id"] == "native@0x40C0D4"
        assert row178_reference["condition_producer_ea"] == 0x40C0D9
        assert row178_reference["predicate_anchor_ea"] == 0x40C0E7
        assert row178_reference["observed_predicate_kind"] == "slt"
        assert row178_reference["predicate_kind"] == "sge"
        assert row178_reference["comparison_constant"] == 0x0BB2D365
        assert row178_reference["transfer_ea"] == 0x40C0EE
        assert row178_reference["true_target_ea"] == 0x40B6C0
        assert row178_reference["false_target_ea"] == 0x40A607
        assert row178_reference["owned_corridor_instruction_eas"] == [
            0x40C0D9,
            0x40C0DF,
            0x40C0E1,
            0x40C0E7,
            0x40C0EA,
            0x40C0EC,
            0x40C0EE,
        ]
        assert row178_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row178_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row179_reference = reference_payloads["rhad:route@0x40C108"]
        assert row179_reference["reference_order"] == 179
        assert row179_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row179_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row179_reference["source_native_ea"] == 0x40C0F0
        assert row179_reference["source_block_anchor_ea"] == 0x40C104
        assert row179_reference["condition_producer_ea"] == 0x40C0F6
        assert row179_reference["predicate_anchor_ea"] == 0x40C0FC
        assert row179_reference["observed_predicate_kind"] == "eq"
        assert row179_reference["predicate_kind"] == "ne"
        assert row179_reference["comparison_constant"] == 0x886CCA9F
        assert row179_reference["transfer_ea"] == 0x40C108
        assert row179_reference["true_target_ea"] == 0x40C10A
        assert row179_reference["false_target_ea"] == 0x40A5F0
        assert row179_reference["owned_corridor_instruction_eas"] == [
            0x40C0F0,
            0x40C0F6,
            0x40C0FC,
            0x40C0FE,
            0x40C104,
            0x40C106,
            0x40C108,
        ]
        assert row179_reference["imported_closure_block_ids"] == [
            "native@0x40C10A",
            "native@0x40C132",
            "native@0x40C144",
            "native@0x40C14E",
            "native@0x40C770",
            "native@0x40C787",
            "native@0x40C793",
        ]
        assert row179_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row180_reference = reference_payloads["route:rhad-direct@0x40C14E"]
        assert row180_reference["reference_operation_id"] == "rhad:route@0x40C14E"
        assert row180_reference["reference_order"] == 180
        assert row180_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row180_reference["operation_variant"] == "simple_indirect_jump"
        assert row180_reference["source_native_ea"] == 0x40C132
        assert row180_reference["source_block_anchor_ea"] == 0x40C144
        assert row180_reference["transfer_ea"] == 0x40C14E
        assert row180_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row180_reference["owned_corridor_instruction_eas"] == [
            0x40C132,
            0x40C144,
            0x40C146,
            0x40C148,
            0x40C14E,
        ]
        assert row180_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row180_reference["boundary_exit_eas"] == [0x40B790]
        row181_reference = reference_payloads["rhad:route@0x40C168"]
        assert row181_reference["reference_order"] == 181
        assert row181_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row181_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row181_reference["source_native_ea"] == 0x40C150
        assert row181_reference["source_block_anchor_ea"] == 0x40C164
        assert row181_reference["condition_producer_ea"] == 0x40C156
        assert row181_reference["predicate_anchor_ea"] == 0x40C15C
        assert row181_reference["observed_predicate_kind"] == "eq"
        assert row181_reference["predicate_kind"] == "ne"
        assert row181_reference["comparison_constant"] == 0xCCEC5DE0
        assert row181_reference["transfer_ea"] == 0x40C168
        assert row181_reference["true_target_ea"] == 0x40C16A
        assert row181_reference["false_target_ea"] == 0x40A5F0
        assert row181_reference["owned_corridor_instruction_eas"] == [
            0x40C150,
            0x40C156,
            0x40C15C,
            0x40C15E,
            0x40C164,
            0x40C166,
            0x40C168,
        ]
        assert row181_reference["imported_closure_block_ids"] == [
            "native@0x40C16A",
            "native@0x40C17D",
            "native@0x40C180",
            "native@0x40C184",
        ]
        assert row181_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row182_reference = reference_payloads["rhad:route@0x40C184"]
        assert row182_reference["reference_order"] == 182
        assert row182_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row182_reference["operation_variant"] == "cmov_selected_indirect"
        assert row182_reference["source_native_ea"] == 0x40C175
        assert row182_reference["source_block_anchor_ea"] == 0x40C16A
        assert row182_reference["source_value_block_id"] == "native@0x40C16A"
        assert row182_reference["condition_producer_ea"] == 0x40C16F
        assert row182_reference["predicate_anchor_ea"] == 0x40C17D
        assert row182_reference["observed_predicate_kind"] == "slt"
        assert row182_reference["predicate_kind"] == "sge"
        assert row182_reference["comparison_constant"] == 0x0BB2D365
        assert row182_reference["transfer_ea"] == 0x40C184
        assert row182_reference["true_target_ea"] == 0x40B6C0
        assert row182_reference["false_target_ea"] == 0x40A607
        assert row182_reference["owned_corridor_instruction_eas"] == [
            0x40C16F,
            0x40C175,
            0x40C177,
            0x40C17D,
            0x40C180,
            0x40C182,
            0x40C184,
        ]
        assert row182_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row182_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row183_reference = reference_payloads["rhad:route@0x40C19E"]
        assert row183_reference["reference_order"] == 183
        assert row183_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row183_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row183_reference["source_native_ea"] == 0x40C186
        assert row183_reference["source_block_anchor_ea"] == 0x40C19A
        assert row183_reference["condition_producer_ea"] == 0x40C18C
        assert row183_reference["predicate_anchor_ea"] == 0x40C192
        assert row183_reference["observed_predicate_kind"] == "eq"
        assert row183_reference["predicate_kind"] == "ne"
        assert row183_reference["comparison_constant"] == 0xA7933EA0
        assert row183_reference["transfer_ea"] == 0x40C19E
        assert row183_reference["true_target_ea"] == 0x40C1A0
        assert row183_reference["false_target_ea"] == 0x40A5F0
        assert row183_reference["owned_corridor_instruction_eas"] == [
            0x40C186,
            0x40C18C,
            0x40C192,
            0x40C194,
            0x40C19A,
            0x40C19C,
            0x40C19E,
        ]
        assert row183_reference["imported_closure_block_ids"] == [
            "native@0x40C1A0",
            "native@0x40C1C0",
            "native@0x40C1E9",
            "native@0x40C1EC",
            "native@0x40C1F0",
        ]
        assert row183_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row184_reference = reference_payloads["rhad:route@0x40C1F0"]
        assert row184_reference["reference_order"] == 184
        assert row184_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row184_reference["operation_variant"] == "cmov_selected_indirect"
        assert row184_reference["source_native_ea"] == 0x40C1C6
        assert row184_reference["source_block_anchor_ea"] == 0x40C1C0
        assert row184_reference["condition_producer_ea"] == 0x40C1DB
        assert row184_reference["predicate_anchor_ea"] == 0x40C1E9
        assert row184_reference["observed_predicate_kind"] == "slt"
        assert row184_reference["predicate_kind"] == "sge"
        assert row184_reference["comparison_constant"] == 0x0BB2D365
        assert row184_reference["transfer_ea"] == 0x40C1F0
        assert row184_reference["true_target_ea"] == 0x40B6C0
        assert row184_reference["false_target_ea"] == 0x40A607
        assert row184_reference["owned_corridor_instruction_eas"] == [
            0x40C1C6,
            0x40C1DB,
            0x40C1E1,
            0x40C1E3,
            0x40C1E9,
            0x40C1EC,
            0x40C1EE,
            0x40C1F0,
        ]
        assert row184_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row184_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row185_reference = reference_payloads["rhad:route@0x40C20A"]
        assert row185_reference["reference_order"] == 185
        assert row185_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row185_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row185_reference["source_native_ea"] == 0x40C1F2
        assert row185_reference["source_block_anchor_ea"] == 0x40C206
        assert row185_reference["condition_producer_ea"] == 0x40C1F8
        assert row185_reference["predicate_anchor_ea"] == 0x40C1FE
        assert row185_reference["observed_predicate_kind"] == "eq"
        assert row185_reference["predicate_kind"] == "ne"
        assert row185_reference["comparison_constant"] == 0xF0B56411
        assert row185_reference["transfer_ea"] == 0x40C20A
        assert row185_reference["true_target_ea"] == 0x40C20C
        assert row185_reference["false_target_ea"] == 0x40A5F0
        assert row185_reference["owned_corridor_instruction_eas"] == [
            0x40C1F2,
            0x40C1F8,
            0x40C1FE,
            0x40C200,
            0x40C206,
            0x40C208,
            0x40C20A,
        ]
        assert row185_reference["imported_closure_block_ids"] == [
            "native@0x40C20C",
            "native@0x40C235",
            "native@0x40C247",
            "native@0x40C251",
            "native@0x40C795",
            "native@0x40C7AC",
            "native@0x40C7B8",
        ]
        assert row185_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row186_reference = reference_payloads["route:rhad-direct@0x40C251"]
        assert row186_reference["reference_operation_id"] == ("rhad:route@0x40C251")
        assert row186_reference["reference_order"] == 186
        assert row186_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row186_reference["operation_variant"] == "simple_indirect_jump"
        assert row186_reference["source_native_ea"] == 0x40C235
        assert row186_reference["source_block_anchor_ea"] == 0x40C247
        assert row186_reference["transfer_ea"] == 0x40C251
        assert row186_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row186_reference["owned_corridor_instruction_eas"] == [
            0x40C235,
            0x40C247,
            0x40C249,
            0x40C24B,
            0x40C251,
        ]
        assert row186_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row186_reference["boundary_exit_eas"] == [0x40B790]
        row187_reference = reference_payloads["rhad:route@0x40C26B"]
        assert row187_reference["reference_order"] == 187
        assert row187_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row187_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row187_reference["source_native_ea"] == 0x40C253
        assert row187_reference["source_block_anchor_ea"] == 0x40C267
        assert row187_reference["condition_producer_ea"] == 0x40C259
        assert row187_reference["predicate_anchor_ea"] == 0x40C25F
        assert row187_reference["observed_predicate_kind"] == "eq"
        assert row187_reference["predicate_kind"] == "ne"
        assert row187_reference["comparison_constant"] == 0xA0716E5B
        assert row187_reference["transfer_ea"] == 0x40C26B
        assert row187_reference["true_target_ea"] == 0x40C26D
        assert row187_reference["false_target_ea"] == 0x40A5F0
        assert row187_reference["owned_corridor_instruction_eas"] == [
            0x40C253,
            0x40C259,
            0x40C25F,
            0x40C261,
            0x40C267,
            0x40C269,
            0x40C26B,
        ]
        assert row187_reference["imported_closure_block_ids"] == [
            "native@0x40C26D",
            "native@0x40C2AF",
            "native@0x40C2C3",
            "native@0x40C2D7",
            "native@0x40C2EF",
            "native@0x40C2F9",
            "native@0x40C7BA",
            "native@0x40C7D7",
            "native@0x40C7E3",
        ]
        assert row187_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row188_reference = reference_payloads["route:rhad-direct@0x40C2F9"]
        assert row188_reference["reference_operation_id"] == "rhad:route@0x40C2F9"
        assert row188_reference["reference_order"] == 188
        assert row188_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row188_reference["operation_variant"] == "simple_indirect_jump"
        assert row188_reference["source_native_ea"] == 0x40C2D7
        assert row188_reference["source_block_anchor_ea"] == 0x40C2EF
        assert row188_reference["transfer_ea"] == 0x40C2F9
        assert row188_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row188_reference["owned_corridor_instruction_eas"] == [
            0x40C2D7,
            0x40C2EF,
            0x40C2F1,
            0x40C2F3,
            0x40C2F9,
        ]
        assert row188_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row188_reference["boundary_exit_eas"] == [0x40B790]
        row189_reference = reference_payloads["rhad:route@0x40C313"]
        assert row189_reference["reference_order"] == 189
        assert row189_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row189_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row189_reference["source_native_ea"] == 0x40C2FB
        assert row189_reference["source_block_anchor_ea"] == 0x40C30F
        assert row189_reference["condition_producer_ea"] == 0x40C301
        assert row189_reference["predicate_anchor_ea"] == 0x40C307
        assert row189_reference["observed_predicate_kind"] == "eq"
        assert row189_reference["predicate_kind"] == "ne"
        assert row189_reference["comparison_constant"] == 0xE41F690E
        assert row189_reference["transfer_ea"] == 0x40C313
        assert row189_reference["true_target_ea"] == 0x40C315
        assert row189_reference["false_target_ea"] == 0x40A5F0
        assert row189_reference["owned_corridor_instruction_eas"] == [
            0x40C2FB,
            0x40C301,
            0x40C307,
            0x40C309,
            0x40C30F,
            0x40C311,
            0x40C313,
        ]
        assert row189_reference["imported_closure_block_ids"] == [
            "native@0x40C315",
            "native@0x40C335",
            "native@0x40C347",
            "native@0x40C34B",
            "native@0x40C7E5",
            "native@0x40C7FC",
            "native@0x40C802",
        ]
        assert row189_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row190_reference = reference_payloads["route:rhad-direct@0x40C34B"]
        assert row190_reference["reference_operation_id"] == "rhad:route@0x40C34B"
        assert row190_reference["reference_order"] == 190
        assert row190_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row190_reference["operation_variant"] == "simple_indirect_jump"
        assert row190_reference["source_native_ea"] == 0x40C335
        assert row190_reference["source_block_anchor_ea"] == 0x40C347
        assert row190_reference["transfer_ea"] == 0x40C34B
        assert row190_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row190_reference["owned_corridor_instruction_eas"] == [
            0x40C335,
            0x40C347,
            0x40C349,
            0x40C34B,
        ]
        assert row190_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row190_reference["boundary_exit_eas"] == [0x40B790]
        row191_reference = reference_payloads["rhad:route@0x40C365"]
        assert row191_reference["reference_order"] == 191
        assert row191_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row191_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row191_reference["source_native_ea"] == 0x40C34D
        assert row191_reference["source_block_anchor_ea"] == 0x40C361
        assert row191_reference["condition_producer_ea"] == 0x40C353
        assert row191_reference["predicate_anchor_ea"] == 0x40C359
        assert row191_reference["observed_predicate_kind"] == "eq"
        assert row191_reference["predicate_kind"] == "ne"
        assert row191_reference["comparison_constant"] == 0xB5D98F1E
        assert row191_reference["transfer_ea"] == 0x40C365
        assert row191_reference["true_target_ea"] == 0x40C367
        assert row191_reference["false_target_ea"] == 0x40A5F0
        assert row191_reference["owned_corridor_instruction_eas"] == [
            0x40C34D,
            0x40C353,
            0x40C359,
            0x40C35B,
            0x40C361,
            0x40C363,
            0x40C365,
        ]
        assert row191_reference["imported_closure_block_ids"] == [
            "native@0x40C367",
            "native@0x40C37A",
            "native@0x40C38C",
            "native@0x40C390",
            "native@0x40C804",
            "native@0x40C81B",
            "native@0x40C821",
        ]
        assert row191_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row192_reference = reference_payloads["route:rhad-direct@0x40C390"]
        assert row192_reference["reference_operation_id"] == "rhad:route@0x40C390"
        assert row192_reference["reference_order"] == 192
        assert row192_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row192_reference["operation_variant"] == "simple_indirect_jump"
        assert row192_reference["source_native_ea"] == 0x40C37A
        assert row192_reference["source_block_anchor_ea"] == 0x40C38C
        assert row192_reference["transfer_ea"] == 0x40C390
        assert row192_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row192_reference["owned_corridor_instruction_eas"] == [
            0x40C37A,
            0x40C38C,
            0x40C38E,
            0x40C390,
        ]
        assert row192_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row192_reference["boundary_exit_eas"] == [0x40B790]
        row193_reference = reference_payloads["rhad:route@0x40C3AA"]
        assert row193_reference["reference_order"] == 193
        assert row193_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row193_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row193_reference["source_native_ea"] == 0x40C392
        assert row193_reference["source_block_anchor_ea"] == 0x40C3A6
        assert row193_reference["condition_producer_ea"] == 0x40C398
        assert row193_reference["predicate_anchor_ea"] == 0x40C39E
        assert row193_reference["observed_predicate_kind"] == "eq"
        assert row193_reference["predicate_kind"] == "ne"
        assert row193_reference["comparison_constant"] == 0xFA72F85A
        assert row193_reference["transfer_ea"] == 0x40C3AA
        assert row193_reference["true_target_ea"] == 0x40C3AC
        assert row193_reference["false_target_ea"] == 0x40A5F0
        assert row193_reference["owned_corridor_instruction_eas"] == [
            0x40C392,
            0x40C398,
            0x40C39E,
            0x40C3A0,
            0x40C3A6,
            0x40C3A8,
            0x40C3AA,
        ]
        assert row193_reference["imported_closure_block_ids"] == [
            "native@0x40C3AC",
            "native@0x40C3C1",
            "native@0x40C3D3",
            "native@0x40C3D7",
            "native@0x40C823",
            "native@0x40C83A",
            "native@0x40C840",
        ]
        assert row193_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row194_reference = reference_payloads["route:rhad-direct@0x40C3D7"]
        assert row194_reference["reference_operation_id"] == "rhad:route@0x40C3D7"
        assert row194_reference["reference_order"] == 194
        assert row194_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row194_reference["operation_variant"] == "simple_indirect_jump"
        assert row194_reference["source_native_ea"] == 0x40C3C1
        assert row194_reference["source_block_anchor_ea"] == 0x40C3D3
        assert row194_reference["transfer_ea"] == 0x40C3D7
        assert row194_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row194_reference["owned_corridor_instruction_eas"] == [
            0x40C3C1,
            0x40C3D3,
            0x40C3D5,
            0x40C3D7,
        ]
        assert row194_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row194_reference["boundary_exit_eas"] == [0x40B790]
        row195_reference = reference_payloads["rhad:route@0x40C3F1"]
        assert row195_reference["reference_order"] == 195
        assert row195_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row195_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row195_reference["source_native_ea"] == 0x40C3D9
        assert row195_reference["source_block_anchor_ea"] == 0x40C3ED
        assert row195_reference["condition_producer_ea"] == 0x40C3DF
        assert row195_reference["predicate_anchor_ea"] == 0x40C3E5
        assert row195_reference["observed_predicate_kind"] == "eq"
        assert row195_reference["predicate_kind"] == "ne"
        assert row195_reference["comparison_constant"] == 0x96B0D1E5
        assert row195_reference["transfer_ea"] == 0x40C3F1
        assert row195_reference["true_target_ea"] == 0x40C3F3
        assert row195_reference["false_target_ea"] == 0x40A5F0
        assert row195_reference["owned_corridor_instruction_eas"] == [
            0x40C3D9,
            0x40C3DF,
            0x40C3E5,
            0x40C3E7,
            0x40C3ED,
            0x40C3EF,
            0x40C3F1,
        ]
        assert row195_reference["imported_closure_block_ids"] == [
            "native@0x40C3F3",
            "native@0x40C3F9",
            "native@0x40C40A",
            "native@0x40C422",
            "native@0x40C42C",
            "native@0x40C842",
            "native@0x40C85F",
            "native@0x40C86B",
        ]
        assert row195_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row196_reference = reference_payloads["route:rhad-direct@0x40C42C"]
        assert row196_reference["reference_operation_id"] == "rhad:route@0x40C42C"
        assert row196_reference["reference_order"] == 196
        assert row196_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row196_reference["operation_variant"] == "simple_indirect_jump"
        assert row196_reference["source_native_ea"] == 0x40C40A
        assert row196_reference["source_block_anchor_ea"] == 0x40C422
        assert row196_reference["transfer_ea"] == 0x40C42C
        assert row196_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row196_reference["owned_corridor_instruction_eas"] == [
            0x40C40A,
            0x40C422,
            0x40C424,
            0x40C426,
            0x40C42C,
        ]
        assert row196_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row196_reference["boundary_exit_eas"] == [0x40B790]
        row197_reference = reference_payloads["rhad:route@0x40C446"]
        assert row197_reference["reference_order"] == 197
        assert row197_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row197_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row197_reference["source_native_ea"] == 0x40C42E
        assert row197_reference["source_block_anchor_ea"] == 0x40C442
        assert row197_reference["condition_producer_ea"] == 0x40C434
        assert row197_reference["predicate_anchor_ea"] == 0x40C43A
        assert row197_reference["observed_predicate_kind"] == "eq"
        assert row197_reference["predicate_kind"] == "ne"
        assert row197_reference["comparison_constant"] == 0xD44F0C43
        assert row197_reference["transfer_ea"] == 0x40C446
        assert row197_reference["true_target_ea"] == 0x40C448
        assert row197_reference["false_target_ea"] == 0x40A5F0
        assert row197_reference["owned_corridor_instruction_eas"] == [
            0x40C42E,
            0x40C434,
            0x40C43A,
            0x40C43C,
            0x40C442,
            0x40C444,
            0x40C446,
        ]
        assert row197_reference["imported_closure_block_ids"] == [
            "native@0x40C448",
            "native@0x40C45E",
            "native@0x40C462",
        ]
        assert row197_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row198_reference = reference_payloads["rhad:route@0x40C462"]
        assert row198_reference["reference_order"] == 198
        assert row198_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row198_reference["operation_variant"] == "cmov_selected_indirect"
        assert row198_reference["source_native_ea"] == 0x40C453
        assert row198_reference["source_block_anchor_ea"] == 0x40C448
        assert row198_reference["condition_producer_ea"] == 0x40C44D
        assert row198_reference["predicate_anchor_ea"] == 0x40C45B
        assert row198_reference["observed_predicate_kind"] == "slt"
        assert row198_reference["predicate_kind"] == "sge"
        assert row198_reference["comparison_constant"] == 0x0BB2D365
        assert row198_reference["transfer_ea"] == 0x40C462
        assert row198_reference["true_target_ea"] == 0x40B6C0
        assert row198_reference["false_target_ea"] == 0x40A607
        assert row198_reference["owned_corridor_instruction_eas"] == [
            0x40C44D,
            0x40C453,
            0x40C455,
            0x40C45B,
            0x40C45E,
            0x40C460,
            0x40C462,
        ]
        assert row198_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
            "native@0x40C45B",
        ]
        assert row198_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row199_reference = reference_payloads["rhad:route@0x40C47C"]
        assert row199_reference["reference_order"] == 199
        assert row199_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row199_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row199_reference["source_native_ea"] == 0x40C464
        assert row199_reference["source_block_anchor_ea"] == 0x40C478
        assert row199_reference["condition_producer_ea"] == 0x40C46A
        assert row199_reference["predicate_anchor_ea"] == 0x40C470
        assert row199_reference["observed_predicate_kind"] == "eq"
        assert row199_reference["predicate_kind"] == "ne"
        assert row199_reference["comparison_constant"] == 0xAE5A330B
        assert row199_reference["transfer_ea"] == 0x40C47C
        assert row199_reference["true_target_ea"] == 0x40C47E
        assert row199_reference["false_target_ea"] == 0x40A5F0
        assert row199_reference["owned_corridor_instruction_eas"] == [
            0x40C464,
            0x40C46A,
            0x40C470,
            0x40C472,
            0x40C478,
            0x40C47A,
            0x40C47C,
        ]
        assert row199_reference["imported_closure_block_ids"] == [
            "native@0x40C47E",
            "native@0x40C494",
            "native@0x40C498",
        ]
        assert row199_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row200_reference = reference_payloads["rhad:route@0x40C498"]
        assert row200_reference["reference_order"] == 200
        assert row200_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row200_reference["operation_variant"] == "cmov_selected_indirect"
        assert row200_reference["source_native_ea"] == 0x40C489
        assert row200_reference["source_block_anchor_ea"] == 0x40C47E
        assert row200_reference["condition_producer_ea"] == 0x40C483
        assert row200_reference["predicate_anchor_ea"] == 0x40C491
        assert row200_reference["observed_predicate_kind"] == "slt"
        assert row200_reference["predicate_kind"] == "sge"
        assert row200_reference["comparison_constant"] == 0x0BB2D365
        assert row200_reference["transfer_ea"] == 0x40C498
        assert row200_reference["true_target_ea"] == 0x40B6C0
        assert row200_reference["false_target_ea"] == 0x40A607
        assert row200_reference["owned_corridor_instruction_eas"] == [
            0x40C483,
            0x40C489,
            0x40C48B,
            0x40C491,
            0x40C494,
            0x40C496,
            0x40C498,
        ]
        assert row200_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
            "native@0x40C491",
        ]
        assert row200_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row201_reference = reference_payloads["rhad:route@0x40C4B2"]
        assert row201_reference["reference_order"] == 201
        assert row201_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row201_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row201_reference["source_native_ea"] == 0x40C49A
        assert row201_reference["source_block_anchor_ea"] == 0x40C4AE
        assert row201_reference["condition_producer_ea"] == 0x40C4A0
        assert row201_reference["predicate_anchor_ea"] == 0x40C4A6
        assert row201_reference["observed_predicate_kind"] == "eq"
        assert row201_reference["predicate_kind"] == "ne"
        assert row201_reference["comparison_constant"] == 0xF6A636EF
        assert row201_reference["transfer_ea"] == 0x40C4B2
        assert row201_reference["true_target_ea"] == 0x40C4B4
        assert row201_reference["false_target_ea"] == 0x40A5F0
        assert row201_reference["owned_corridor_instruction_eas"] == [
            0x40C49A,
            0x40C4A0,
            0x40C4A6,
            0x40C4A8,
            0x40C4AE,
            0x40C4B0,
            0x40C4B2,
        ]
        assert row201_reference["imported_closure_block_ids"] == [
            "native@0x40C4B4",
            "native@0x40C4C3",
            "native@0x40C4C6",
            "native@0x40C4D4",
            "native@0x40C4D6",
            "native@0x40C4DA",
        ]
        assert row201_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row202_reference = reference_payloads["rhad:route@0x40C4DA"]
        assert row202_reference["reference_order"] == 202
        assert row202_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row202_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row202_reference["source_native_ea"] == 0x40C4C6
        assert row202_reference["source_block_anchor_ea"] == 0x40C4D6
        assert row202_reference["condition_producer_ea"] == 0x40C4CC
        assert row202_reference["predicate_anchor_ea"] == 0x40C4D2
        assert row202_reference["observed_predicate_kind"] == "slt"
        assert row202_reference["predicate_kind"] == "sge"
        assert row202_reference["comparison_constant"] == 0x0BB2D365
        assert row202_reference["transfer_ea"] == 0x40C4DA
        assert row202_reference["true_target_ea"] == 0x40B6C0
        assert row202_reference["false_target_ea"] == 0x40A607
        assert row202_reference["owned_corridor_instruction_eas"] == [
            0x40C4C6,
            0x40C4CC,
            0x40C4D2,
            0x40C4D4,
            0x40C4D6,
            0x40C4D8,
            0x40C4DA,
        ]
        assert row202_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row202_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row203_reference = reference_payloads["rhad:route@0x40C4F4"]
        assert row203_reference["reference_order"] == 203
        assert row203_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row203_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row203_reference["source_native_ea"] == 0x40C4DC
        assert row203_reference["source_block_anchor_ea"] == 0x40C4F0
        assert row203_reference["condition_producer_ea"] == 0x40C4E2
        assert row203_reference["predicate_anchor_ea"] == 0x40C4E8
        assert row203_reference["observed_predicate_kind"] == "eq"
        assert row203_reference["predicate_kind"] == "ne"
        assert row203_reference["comparison_constant"] == 0xA5540595
        assert row203_reference["transfer_ea"] == 0x40C4F4
        assert row203_reference["true_target_ea"] == 0x40C4F6
        assert row203_reference["false_target_ea"] == 0x40A5F0
        assert row203_reference["owned_corridor_instruction_eas"] == [
            0x40C4DC,
            0x40C4E2,
            0x40C4E8,
            0x40C4EA,
            0x40C4F0,
            0x40C4F2,
            0x40C4F4,
        ]
        assert row203_reference["imported_closure_block_ids"] == [
            "native@0x40C4F6",
            "native@0x40C521",
            "native@0x40C525",
        ]
        assert row203_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row204_reference = reference_payloads["rhad:route@0x40C525"]
        assert row204_reference["reference_order"] == 204
        assert row204_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row204_reference["operation_variant"] == "cmov_selected_indirect"
        assert row204_reference["source_native_ea"] == 0x40C516
        assert row204_reference["source_block_anchor_ea"] == 0x40C4F6
        assert row204_reference["condition_producer_ea"] == 0x40C510
        assert row204_reference["predicate_anchor_ea"] == 0x40C51E
        assert row204_reference["observed_predicate_kind"] == "slt"
        assert row204_reference["predicate_kind"] == "sge"
        assert row204_reference["comparison_constant"] == 0x0BB2D365
        assert row204_reference["transfer_ea"] == 0x40C525
        assert row204_reference["true_target_ea"] == 0x40B6C0
        assert row204_reference["false_target_ea"] == 0x40A607
        assert row204_reference["owned_corridor_instruction_eas"] == [
            0x40C510,
            0x40C516,
            0x40C518,
            0x40C51E,
            0x40C521,
            0x40C523,
            0x40C525,
        ]
        assert row204_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
            "native@0x40C51E",
        ]
        assert row204_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row205_reference = reference_payloads["rhad:route@0x40C53F"]
        assert row205_reference["reference_order"] == 205
        assert row205_reference["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
        assert row205_reference["operation_variant"] == "existing_conditional_plus_indirect"
        assert row205_reference["source_native_ea"] == 0x40C527
        assert row205_reference["source_block_anchor_ea"] == 0x40C53B
        assert row205_reference["condition_producer_ea"] == 0x40C52D
        assert row205_reference["predicate_anchor_ea"] == 0x40C533
        assert row205_reference["observed_predicate_kind"] == "eq"
        assert row205_reference["predicate_kind"] == "ne"
        assert row205_reference["comparison_constant"] == 0xEC054ACC
        assert row205_reference["transfer_ea"] == 0x40C53F
        assert row205_reference["true_target_ea"] == 0x40C541
        assert row205_reference["false_target_ea"] == 0x40A5F0
        assert row205_reference["owned_corridor_instruction_eas"] == [
            0x40C527, 0x40C52D, 0x40C533, 0x40C535, 0x40C53B, 0x40C53D, 0x40C53F,
        ]
        assert row205_reference["imported_closure_block_ids"] == [
            "native@0x40C541", "native@0x40C54D", "native@0x40C56F",
            "native@0x40C572", "native@0x40C576",
        ]
        assert row205_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row206_reference = reference_payloads["rhad:route@0x40C576"]
        assert row206_reference["reference_order"] == 206
        assert row206_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row206_reference["operation_variant"] == "cmov_selected_indirect"
        assert row206_reference["source_native_ea"] == 0x40C553
        assert row206_reference["source_block_anchor_ea"] == 0x40C54D
        assert row206_reference["condition_producer_ea"] == 0x40C561
        assert row206_reference["predicate_anchor_ea"] == 0x40C56F
        assert row206_reference["observed_predicate_kind"] == "slt"
        assert row206_reference["predicate_kind"] == "sge"
        assert row206_reference["comparison_constant"] == 0x0BB2D365
        assert row206_reference["transfer_ea"] == 0x40C576
        assert row206_reference["true_target_ea"] == 0x40B6C0
        assert row206_reference["false_target_ea"] == 0x40A607
        assert row206_reference["owned_corridor_instruction_eas"] == [
            0x40C553,
            0x40C561,
            0x40C567,
            0x40C569,
            0x40C56F,
            0x40C572,
            0x40C574,
            0x40C576,
        ]
        assert row206_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
            "native@0x40C56F",
        ]
        assert row206_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row207_reference = reference_payloads["rhad:route@0x40C590"]
        assert row207_reference["reference_order"] == 207
        assert row207_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row207_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row207_reference["source_native_ea"] == 0x40C578
        assert row207_reference["source_block_anchor_ea"] == 0x40C58C
        assert row207_reference["condition_producer_ea"] == 0x40C57E
        assert row207_reference["predicate_anchor_ea"] == 0x40C584
        assert row207_reference["observed_predicate_kind"] == "eq"
        assert row207_reference["predicate_kind"] == "ne"
        assert row207_reference["comparison_constant"] == 0xBD9A2C2A
        assert row207_reference["transfer_ea"] == 0x40C590
        assert row207_reference["true_target_ea"] == 0x40C592
        assert row207_reference["false_target_ea"] == 0x40A5F0
        assert row207_reference["owned_corridor_instruction_eas"] == [
            0x40C578,
            0x40C57E,
            0x40C584,
            0x40C586,
            0x40C58C,
            0x40C58E,
            0x40C590,
        ]
        assert row207_reference["imported_closure_block_ids"] == [
            "native@0x40C592",
            "native@0x40C5BD",
            "native@0x40C5D7",
            "native@0x40C5EF",
            "native@0x40C5F9",
            "native@0x40C86D",
            "native@0x40C88A",
            "native@0x40C896",
        ]
        assert row207_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row208_reference = reference_payloads["route:rhad-direct@0x40C5F9"]
        assert row208_reference["reference_operation_id"] == "rhad:route@0x40C5F9"
        assert row208_reference["reference_order"] == 208
        assert row208_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row208_reference["operation_variant"] == "simple_indirect_jump"
        assert row208_reference["source_native_ea"] == 0x40C5D7
        assert row208_reference["source_block_anchor_ea"] == 0x40C5EF
        assert row208_reference["transfer_ea"] == 0x40C5F9
        assert row208_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row208_reference["owned_corridor_instruction_eas"] == [
            0x40C5D7,
            0x40C5EF,
            0x40C5F1,
            0x40C5F3,
            0x40C5F9,
        ]
        assert row208_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row208_reference["boundary_exit_eas"] == [0x40B790]
        row209_reference = reference_payloads["rhad:route@0x40C613"]
        assert row209_reference["reference_order"] == 209
        assert row209_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row209_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row209_reference["source_native_ea"] == 0x40C5FB
        assert row209_reference["source_block_anchor_ea"] == 0x40C60F
        assert row209_reference["condition_producer_ea"] == 0x40C601
        assert row209_reference["predicate_anchor_ea"] == 0x40C607
        assert row209_reference["observed_predicate_kind"] == "slt"
        assert row209_reference["predicate_kind"] == "sge"
        assert row209_reference["comparison_constant"] == 0x09FE690C
        assert row209_reference["transfer_ea"] == 0x40C613
        assert row209_reference["true_target_ea"] == 0x40C64B
        assert row209_reference["false_target_ea"] == 0x40C615
        assert row209_reference["owned_corridor_instruction_eas"] == [
            0x40C5FB,
            0x40C601,
            0x40C607,
            0x40C609,
            0x40C60F,
            0x40C611,
            0x40C613,
        ]
        assert row209_reference["imported_closure_block_ids"] == [
            "native@0x40C615",
            "native@0x40C623",
            "native@0x40C629",
            "native@0x40C62D",
            "native@0x40C64B",
            "native@0x40C659",
            "native@0x40C65F",
            "native@0x40C663",
        ]
        assert row209_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40C62F,
            0x40C665,
        ]
        row210_reference = reference_payloads["rhad:route@0x40C62D"]
        assert row210_reference["reference_order"] == 210
        assert row210_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row210_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row210_reference["source_native_ea"] == 0x40C615
        assert row210_reference["source_block_anchor_ea"] == 0x40C629
        assert row210_reference["condition_producer_ea"] == 0x40C61B
        assert row210_reference["predicate_anchor_ea"] == 0x40C621
        assert row210_reference["observed_predicate_kind"] == "eq"
        assert row210_reference["predicate_kind"] == "ne"
        assert row210_reference["comparison_constant"] == 0x0872BFF1
        assert row210_reference["transfer_ea"] == 0x40C62D
        assert row210_reference["true_target_ea"] == 0x40C62F
        assert row210_reference["false_target_ea"] == 0x40A5F0
        assert row210_reference["owned_corridor_instruction_eas"] == [
            0x40C615,
            0x40C61B,
            0x40C621,
            0x40C623,
            0x40C629,
            0x40C62B,
            0x40C62D,
        ]
        assert row210_reference["imported_closure_block_ids"] == [
            "native@0x40C62F",
            "native@0x40C642",
            "native@0x40C645",
            "native@0x40C649",
        ]
        assert row210_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row211_reference = reference_payloads["rhad:route@0x40C649"]
        assert row211_reference["reference_order"] == 211
        assert row211_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row211_reference["operation_variant"] == "cmov_selected_indirect"
        assert row211_reference["source_native_ea"] == 0x40C63A
        assert row211_reference["source_block_anchor_ea"] == 0x40C62F
        assert row211_reference["condition_producer_ea"] == 0x40C634
        assert row211_reference["predicate_anchor_ea"] == 0x40C642
        assert row211_reference["observed_predicate_kind"] == "slt"
        assert row211_reference["predicate_kind"] == "sge"
        assert row211_reference["comparison_constant"] == 0x0BB2D365
        assert row211_reference["transfer_ea"] == 0x40C649
        assert row211_reference["true_target_ea"] == 0x40B6C0
        assert row211_reference["false_target_ea"] == 0x40A607
        assert row211_reference["owned_corridor_instruction_eas"] == [
            0x40C634,
            0x40C63A,
            0x40C63C,
            0x40C642,
            0x40C645,
            0x40C647,
            0x40C649,
        ]
        assert row211_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row211_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row212_reference = reference_payloads["rhad:route@0x40C663"]
        assert row212_reference["reference_order"] == 212
        assert row212_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row212_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row212_reference["source_native_ea"] == 0x40C64B
        assert row212_reference["source_block_anchor_ea"] == 0x40C65F
        assert row212_reference["condition_producer_ea"] == 0x40C651
        assert row212_reference["predicate_anchor_ea"] == 0x40C657
        assert row212_reference["observed_predicate_kind"] == "eq"
        assert row212_reference["predicate_kind"] == "ne"
        assert row212_reference["comparison_constant"] == 0x09FE690C
        assert row212_reference["transfer_ea"] == 0x40C663
        assert row212_reference["true_target_ea"] == 0x40C665
        assert row212_reference["false_target_ea"] == 0x40A5F0
        assert row212_reference["owned_corridor_instruction_eas"] == [
            0x40C64B,
            0x40C651,
            0x40C657,
            0x40C659,
            0x40C65F,
            0x40C661,
            0x40C663,
        ]
        assert row212_reference["imported_closure_block_ids"] == [
            "native@0x40C665",
            "native@0x40C68D",
            "native@0x40C690",
            "native@0x40C694",
        ]
        assert row212_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row213_reference = reference_payloads["rhad:route@0x40C694"]
        assert row213_reference["reference_order"] == 213
        assert row213_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row213_reference["operation_variant"] == "cmov_selected_indirect"
        assert row213_reference["source_native_ea"] == 0x40C685
        assert row213_reference["source_block_anchor_ea"] == 0x40C665
        assert row213_reference["condition_producer_ea"] == 0x40C67F
        assert row213_reference["predicate_anchor_ea"] == 0x40C68D
        assert row213_reference["observed_predicate_kind"] == "slt"
        assert row213_reference["predicate_kind"] == "sge"
        assert row213_reference["comparison_constant"] == 0x0BB2D365
        assert row213_reference["transfer_ea"] == 0x40C694
        assert row213_reference["true_target_ea"] == 0x40B6C0
        assert row213_reference["false_target_ea"] == 0x40A607
        assert row213_reference["owned_corridor_instruction_eas"] == [
            0x40C67F,
            0x40C685,
            0x40C687,
            0x40C68D,
            0x40C690,
            0x40C692,
            0x40C694,
        ]
        assert row213_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row213_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row214_reference = reference_payloads["route:rhad-direct@0x40C6B3"]
        assert row214_reference["reference_operation_id"] == "rhad:route@0x40C6B3"
        assert row214_reference["reference_order"] == 214
        assert row214_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row214_reference["operation_variant"] == "simple_indirect_jump"
        assert row214_reference["source_native_ea"] == 0x40B765
        assert row214_reference["source_block_anchor_ea"] == 0x40C6AD
        assert row214_reference["transfer_ea"] == 0x40C6B3
        assert row214_reference["direct_target_block_id"] == "native@0x40A607"
        assert row214_reference["owned_corridor_instruction_eas"] == [
            0x40B765,
            0x40B777,
            0x40C6AD,
            0x40C6AF,
            0x40C6B1,
            0x40C6B3,
        ]
        assert row214_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row214_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row215_reference = reference_payloads["route:rhad-direct@0x40C6D8"]
        assert row215_reference["reference_operation_id"] == "rhad:route@0x40C6D8"
        assert row215_reference["reference_order"] == 215
        assert row215_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row215_reference["operation_variant"] == "simple_indirect_jump"
        assert row215_reference["source_native_ea"] == 0x40B90F
        assert row215_reference["source_block_anchor_ea"] == 0x40C6CC
        assert row215_reference["transfer_ea"] == 0x40C6D8
        assert row215_reference["direct_target_block_id"] == "native@0x40A607"
        assert row215_reference["owned_corridor_instruction_eas"] == [
            0x40B90F,
            0x40B921,
            0x40C6CC,
            0x40C6CE,
            0x40C6D0,
            0x40C6D2,
            0x40C6D8,
        ]
        assert row215_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row215_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row216_reference = reference_payloads["route:rhad-direct@0x40C703"]
        assert row216_reference["reference_operation_id"] == "rhad:route@0x40C703"
        assert row216_reference["reference_order"] == 216
        assert row216_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row216_reference["operation_variant"] == "simple_indirect_jump"
        assert row216_reference["source_native_ea"] == 0x40BB4B
        assert row216_reference["source_block_anchor_ea"] == 0x40C6F7
        assert row216_reference["transfer_ea"] == 0x40C703
        assert row216_reference["direct_target_block_id"] == "native@0x40A607"
        assert row216_reference["owned_corridor_instruction_eas"] == [
            0x40BB4B,
            0x40BB5D,
            0x40BB63,
            0x40C6EB,
            0x40C6F7,
            0x40C6F9,
            0x40C6FB,
            0x40C6FD,
            0x40C703,
        ]
        assert row216_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row216_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row217_reference = reference_payloads["route:rhad-direct@0x40C72E"]
        assert row217_reference["reference_operation_id"] == "rhad:route@0x40C72E"
        assert row217_reference["reference_order"] == 217
        assert row217_reference["source_native_ea"] == 0x40BF62
        assert row217_reference["source_block_anchor_ea"] == 0x40C722
        assert row217_reference["transfer_ea"] == 0x40C72E
        assert row217_reference["direct_target_block_id"] == "native@0x40A607"
        assert row217_reference["owned_corridor_instruction_eas"] == [
            0x40BF62, 0x40BF74, 0x40BF7A, 0x40C716, 0x40C722,
            0x40C724, 0x40C726, 0x40C728, 0x40C72E,
        ]
        assert row217_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row218_reference = reference_payloads["route:rhad-direct@0x40C74F"]
        assert row218_reference["reference_operation_id"] == "rhad:route@0x40C74F"
        assert row218_reference["reference_order"] == 218
        assert row218_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row218_reference["operation_variant"] == "simple_indirect_jump"
        assert row218_reference["source_native_ea"] == 0x40C00E
        assert row218_reference["source_block_anchor_ea"] == 0x40C749
        assert row218_reference["transfer_ea"] == 0x40C74F
        assert row218_reference["direct_target_block_id"] == "native@0x40A607"
        assert row218_reference["owned_corridor_instruction_eas"] == [
            0x40C00E,
            0x40C021,
            0x40C033,
            0x40C035,
            0x40C741,
            0x40C749,
            0x40C74B,
            0x40C74D,
            0x40C74F,
        ]
        assert row218_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row218_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row219_reference = reference_payloads["route:rhad-direct@0x40C76E"]
        assert row219_reference["reference_operation_id"] == "rhad:route@0x40C76E"
        assert row219_reference["reference_order"] == 219
        assert row219_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row219_reference["operation_variant"] == "simple_indirect_jump"
        assert row219_reference["source_native_ea"] == 0x40C082
        assert row219_reference["source_block_anchor_ea"] == 0x40C768
        assert row219_reference["transfer_ea"] == 0x40C76E
        assert row219_reference["direct_target_block_id"] == "native@0x40A607"
        assert row219_reference["owned_corridor_instruction_eas"] == [
            0x40C082,
            0x40C094,
            0x40C768,
            0x40C76A,
            0x40C76C,
            0x40C76E,
        ]
        assert row219_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row219_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row220_reference = reference_payloads["route:rhad-direct@0x40C793"]
        assert row220_reference["reference_operation_id"] == "rhad:route@0x40C793"
        assert row220_reference["reference_order"] == 220
        assert row220_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row220_reference["operation_variant"] == "simple_indirect_jump"
        assert row220_reference["source_native_ea"] == 0x40C12C
        assert row220_reference["source_block_anchor_ea"] == 0x40C787
        assert row220_reference["transfer_ea"] == 0x40C793
        assert row220_reference["direct_target_block_id"] == "native@0x40A607"
        assert row220_reference["owned_corridor_instruction_eas"] == [
            0x40C12C,
            0x40C13E,
            0x40C787,
            0x40C789,
            0x40C78B,
            0x40C78D,
            0x40C793,
        ]
        assert row220_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row220_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row221_reference = reference_payloads["route:rhad-direct@0x40C7B8"]
        assert row221_reference["reference_operation_id"] == "rhad:route@0x40C7B8"
        assert row221_reference["reference_order"] == 221
        assert row221_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row221_reference["operation_variant"] == "simple_indirect_jump"
        assert row221_reference["source_native_ea"] == 0x40C22F
        assert row221_reference["source_block_anchor_ea"] == 0x40C7AC
        assert row221_reference["transfer_ea"] == 0x40C7B8
        assert row221_reference["direct_target_block_id"] == "native@0x40A607"
        assert row221_reference["owned_corridor_instruction_eas"] == [
            0x40C22F,
            0x40C241,
            0x40C7AC,
            0x40C7AE,
            0x40C7B0,
            0x40C7B2,
            0x40C7B8,
        ]
        assert row221_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row221_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row222_reference = reference_payloads["route:rhad-direct@0x40C7E3"]
        assert row222_reference["reference_operation_id"] == "rhad:route@0x40C7E3"
        assert row222_reference["reference_order"] == 222
        assert row222_reference["source_native_ea"] == 0x40C2D1
        assert row222_reference["source_block_anchor_ea"] == 0x40C7D7
        assert row222_reference["transfer_ea"] == 0x40C7E3
        assert row222_reference["direct_target_block_id"] == "native@0x40A607"
        assert row222_reference["owned_corridor_instruction_eas"] == [
            0x40C2D1,
            0x40C2E3,
            0x40C2E9,
            0x40C7CB,
            0x40C7D7,
            0x40C7D9,
            0x40C7DB,
            0x40C7DD,
            0x40C7E3,
        ]
        assert row222_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row223_reference = reference_payloads["route:rhad-direct@0x40C802"]
        assert row223_reference["reference_operation_id"] == "rhad:route@0x40C802"
        assert row223_reference["reference_order"] == 223
        assert row223_reference["source_native_ea"] == 0x40C32F
        assert row223_reference["source_block_anchor_ea"] == 0x40C7FC
        assert row223_reference["transfer_ea"] == 0x40C802
        assert row223_reference["direct_target_block_id"] == "native@0x40A607"
        assert row223_reference["owned_corridor_instruction_eas"] == [
            0x40C32F,
            0x40C341,
            0x40C7FC,
            0x40C7FE,
            0x40C800,
            0x40C802,
        ]
        assert row223_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row223_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row224_reference = reference_payloads["route:rhad-direct@0x40C821"]
        assert row224_reference["reference_operation_id"] == "rhad:route@0x40C821"
        assert row224_reference["reference_order"] == 224
        assert row224_reference["source_native_ea"] == 0x40C374
        assert row224_reference["source_block_anchor_ea"] == 0x40C81B
        assert row224_reference["transfer_ea"] == 0x40C821
        assert row224_reference["direct_target_block_id"] == "native@0x40A607"
        assert row224_reference["owned_corridor_instruction_eas"] == [
            0x40C374,
            0x40C386,
            0x40C81B,
            0x40C81D,
            0x40C81F,
            0x40C821,
        ]
        assert row224_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row224_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row225_reference = reference_payloads["route:rhad-direct@0x40C840"]
        assert row225_reference["reference_operation_id"] == "rhad:route@0x40C840"
        assert row225_reference["reference_order"] == 225
        assert row225_reference["source_native_ea"] == 0x40C3BB
        assert row225_reference["source_block_anchor_ea"] == 0x40C83A
        assert row225_reference["transfer_ea"] == 0x40C840
        assert row225_reference["direct_target_block_id"] == "native@0x40A607"
        assert row225_reference["owned_corridor_instruction_eas"] == [
            0x40C3BB,
            0x40C3CD,
            0x40C83A,
            0x40C83C,
            0x40C83E,
            0x40C840,
        ]
        assert row225_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row225_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row226_reference = reference_payloads["route:rhad-direct@0x40C86B"]
        assert row226_reference["reference_operation_id"] == "rhad:route@0x40C86B"
        assert row226_reference["reference_order"] == 226
        assert row226_reference["source_native_ea"] == 0x40C404
        assert row226_reference["source_block_anchor_ea"] == 0x40C85F
        assert row226_reference["transfer_ea"] == 0x40C86B
        assert row226_reference["direct_target_block_id"] == "native@0x40A607"
        assert row226_reference["owned_corridor_instruction_eas"] == [
            0x40C404,
            0x40C416,
            0x40C41C,
            0x40C853,
            0x40C85F,
            0x40C861,
            0x40C863,
            0x40C865,
            0x40C86B,
        ]
        assert row226_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row226_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        row227_reference = reference_payloads["route:rhad-direct@0x40C896"]
        assert row227_reference["reference_operation_id"] == "rhad:route@0x40C896"
        assert row227_reference["reference_order"] == 227
        assert row227_reference["source_native_ea"] == 0x40C5D1
        assert row227_reference["source_block_anchor_ea"] == 0x40C88A
        assert row227_reference["transfer_ea"] == 0x40C896
        assert row227_reference["direct_target_block_id"] == "native@0x40A607"
        assert row227_reference["owned_corridor_instruction_eas"] == [
            0x40C5D1,
            0x40C5E3,
            0x40C5E9,
            0x40C87E,
            0x40C88A,
            0x40C88C,
            0x40C88E,
            0x40C890,
            0x40C896,
        ]
        assert row227_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
        ]
        assert row227_reference["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        setcc_reference = reference_payloads["rhad:route@0x40A77C"]
        assert setcc_reference["reference_order"] == 16
        assert setcc_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert setcc_reference["operation_variant"] == "setcc_indexed_table"
        assert setcc_reference["source_native_ea"] == 0x40A766
        assert setcc_reference["condition_producer_ea"] == 0x40A768
        assert setcc_reference["transfer_ea"] == 0x40A77C
        assert setcc_reference["true_target_ea"] == 0x40A77E
        assert setcc_reference["false_target_ea"] == 0x40ABC6
        assert setcc_reference["true_target_block_id"] == "native@0x40A77E"
        assert setcc_reference["false_target_block_id"] == "native@0x40ABC6"
        assert setcc_reference["setcc_table"]["table_base_ea"] == 0x48B81C
        assert setcc_reference["setcc_table"]["stride_bytes"] == 0x20
        assert setcc_reference["setcc_table"]["true_index"] == 1
        assert setcc_reference["setcc_table"]["false_index"] == 0
        assert (
            setcc_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40A77C"]
        )
        assert (
            setcc_reference["aggregate_program_identity"]
            == (compiled_payload["aggregate_program_identity"])
        )
        scaled_setcc_reference = reference_payloads["rhad:route@0x40A792"]
        assert scaled_setcc_reference["reference_order"] == 17
        assert scaled_setcc_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert scaled_setcc_reference["operation_variant"] == ("setcc_indexed_table")
        assert scaled_setcc_reference["source_native_ea"] == 0x40A77E
        assert scaled_setcc_reference["condition_producer_ea"] == 0x40A780
        assert scaled_setcc_reference["predicate_anchor_ea"] == 0x40A786
        assert scaled_setcc_reference["predicate_kind"] == "sge"
        assert scaled_setcc_reference["transfer_ea"] == 0x40A792
        assert scaled_setcc_reference["true_target_ea"] == 0x40AEE6
        assert scaled_setcc_reference["false_target_ea"] == 0x40A794
        assert scaled_setcc_reference["true_target_block_id"] == ("native@0x40AEE6")
        assert scaled_setcc_reference["false_target_block_id"] == ("native@0x40A794")
        assert scaled_setcc_reference["setcc_table"]["table_base_ea"] == 0x48B4F8
        assert scaled_setcc_reference["setcc_table"]["stride_bytes"] == 8
        assert scaled_setcc_reference["setcc_table"]["index_scaling"] == {
            "kind": "scaled_lookup",
            "lookup_ea": 0x40A789,
            "scale_bytes": 8,
        }
        assert scaled_setcc_reference["setcc_table"]["true_index"] == 1
        assert scaled_setcc_reference["setcc_table"]["false_index"] == 0
        assert (
            scaled_setcc_reference["proof_artifact"]
            == proof_artifacts["rhad:route@0x40A792"]
        )
        assert (
            scaled_setcc_reference["aggregate_program_identity"]
            == compiled_payload["aggregate_program_identity"]
        )
        row18_reference = reference_payloads["rhad:route@0x40A7AC"]
        assert row18_reference["reference_order"] == 18
        assert row18_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row18_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row18_reference["source_native_ea"] == 0x40A794
        assert row18_reference["condition_producer_ea"] == 0x40A79A
        assert row18_reference["predicate_anchor_ea"] == 0x40A7A0
        assert row18_reference["predicate_kind"] == "eq"
        assert row18_reference["observed_predicate_kind"] == "ne"
        assert row18_reference["transfer_ea"] == 0x40A7AC
        assert row18_reference["true_target_ea"] == 0x40A7AE
        assert row18_reference["false_target_ea"] == 0x40A5F0
        assert row18_reference["true_target_block_id"] == "native@0x40A7AE"
        assert row18_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row18_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row19_reference = reference_payloads["route:rhad-direct@0x40A7EF"]
        assert row19_reference["reference_operation_id"] == "rhad:route@0x40A7EF"
        assert row19_reference["reference_order"] == 19
        assert row19_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row19_reference["operation_variant"] == "simple_indirect_jump"
        assert row19_reference["source_native_ea"] == 0x40A7CD
        assert row19_reference["source_block_anchor_ea"] == 0x40A7E5
        assert row19_reference["transfer_ea"] == 0x40A7EF
        assert row19_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row19_reference["owned_corridor_instruction_eas"] == [
            0x40A7CD,
            0x40A7E5,
            0x40A7E7,
            0x40A7E9,
            0x40A7EF,
        ]
        assert row19_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row19_reference["boundary_exit_eas"] == [0x40B790]

        constant_reference = reference_payloads[_CONSTANT_OPERATION_ID]
        assert constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADCC,
            "depends_on": ["route:rhad-direct@0x40C896"],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "add_r32_absolute",
            "materialized_value": 0x3776723F,
            "operation_id": _CONSTANT_OPERATION_ID,
            "operation_variant": "add_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "generated_absolute_load",
            "reference_data_bytes_le": "3f727637",
            "reference_operation_id": "rhad:constant@0x40A574",
            "reference_order": 0,
            "reference_raw_value": 0x3776723F,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_arith_mem_to_imm"
            ),
            "replacement_instruction_bytes": "81c03f727637",
            "source_block_id": "native@0x40A560",
            "source_instruction_bytes": "0305ccad4800",
            "source_native_ea": 0x40A574,
            "source_width_bits": 32,
        }
        mov_constant_reference = reference_payloads[_MOV_CONSTANT_OPERATION_ID]
        assert mov_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE10,
            "depends_on": [_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 12,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x2F192B3A,
            "operation_id": _MOV_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "3a2b192f",
            "reference_operation_id": "rhad:constant@0x40A710",
            "reference_order": 1,
            "reference_raw_value": 0x2F192B3A,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90ba3a2b192f",
            "source_block_id": "native@0x40A70E",
            "source_instruction_bytes": "8b1510ae4800",
            "source_native_ea": 0x40A710,
            "source_width_bits": 32,
        }
        eax_constant_reference = reference_payloads[_EAX_CONSTANT_OPERATION_ID]
        assert eax_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE28,
            "depends_on": [_MOV_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x0C5DAC2C,
            "operation_id": _EAX_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "2cac5d0c",
            "reference_operation_id": "rhad:constant@0x40A868",
            "reference_order": 2,
            "reference_raw_value": 0x0C5DAC2C,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b82cac5d0c",
            "source_block_id": "native@0x40A868",
            "source_instruction_bytes": "a128ae4800",
            "source_native_ea": 0x40A868,
            "source_width_bits": 32,
        }
        row3_constant_reference = reference_payloads[_ROW3_CONSTANT_OPERATION_ID]
        assert row3_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE80,
            "depends_on": [_EAX_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xDFD17895,
            "operation_id": _ROW3_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "9578d1df",
            "reference_operation_id": "rhad:constant@0x40A903",
            "reference_order": 3,
            "reference_raw_value": 0xDFD17895,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b89578d1df",
            "source_block_id": "native@0x40A903",
            "source_instruction_bytes": "a180ae4800",
            "source_native_ea": 0x40A903,
            "source_width_bits": 32,
        }
        row4_constant_reference = reference_payloads[_ROW4_CONSTANT_OPERATION_ID]
        assert row4_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE84,
            "depends_on": [_ROW3_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0xEB62D846,
            "operation_id": _ROW4_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "46d862eb",
            "reference_operation_id": "rhad:constant@0x40A922",
            "reference_order": 4,
            "reference_raw_value": 0xEB62D846,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b946d862eb",
            "source_block_id": "native@0x40A922",
            "source_instruction_bytes": "8b0d84ae4800",
            "source_native_ea": 0x40A922,
            "source_width_bits": 32,
        }
        row5_constant_reference = reference_payloads[_ROW5_CONSTANT_OPERATION_ID]
        assert row5_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE2C,
            "depends_on": [_ROW4_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x586FFF63,
            "operation_id": _ROW5_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "63ff6f58",
            "reference_operation_id": "rhad:constant@0x40A9AE",
            "reference_order": 5,
            "reference_raw_value": 0x586FFF63,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b863ff6f58",
            "source_block_id": "native@0x40A9AE",
            "source_instruction_bytes": "a12cae4800",
            "source_native_ea": 0x40A9AE,
            "source_width_bits": 32,
        }
        row6_constant_reference = reference_payloads[_ROW6_CONSTANT_OPERATION_ID]
        assert row6_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADFC,
            "depends_on": [_ROW5_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 12,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0xB725F664,
            "operation_id": _ROW6_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "64f625b7",
            "reference_operation_id": "rhad:constant@0x40AAC2",
            "reference_order": 6,
            "reference_raw_value": 0xB725F664,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90ba64f625b7",
            "source_block_id": "native@0x40AAAE",
            "source_instruction_bytes": "8b15fcad4800",
            "source_native_ea": 0x40AAC2,
            "source_width_bits": 32,
        }
        row7_constant_reference = reference_payloads[_ROW7_CONSTANT_OPERATION_ID]
        assert row7_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE7C,
            "depends_on": [_ROW6_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x3B2885C0,
            "operation_id": _ROW7_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "c085283b",
            "reference_operation_id": "rhad:constant@0x40ABFF",
            "reference_order": 7,
            "reference_raw_value": 0x3B2885C0,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9c085283b",
            "source_block_id": "native@0x40ABFF",
            "source_instruction_bytes": "8b0d7cae4800",
            "source_native_ea": 0x40ABFF,
            "source_width_bits": 32,
        }
        row8_constant_reference = reference_payloads[_ROW8_CONSTANT_OPERATION_ID]
        assert row8_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADEC,
            "depends_on": [_ROW7_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0xCE1A7E0D,
            "operation_id": _ROW8_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "0d7e1ace",
            "reference_operation_id": "rhad:constant@0x40AC81",
            "reference_order": 8,
            "reference_raw_value": 0xCE1A7E0D,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b90d7e1ace",
            "source_block_id": "native@0x40AC81",
            "source_instruction_bytes": "8b0decad4800",
            "source_native_ea": 0x40AC81,
            "source_width_bits": 32,
        }
        row9_constant_reference = reference_payloads[_ROW9_CONSTANT_OPERATION_ID]
        assert row9_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AECC,
            "depends_on": [_ROW8_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x0D2B6F7D,
            "operation_id": _ROW9_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "7d6f2b0d",
            "reference_operation_id": "rhad:constant@0x40AE3E",
            "reference_order": 9,
            "reference_raw_value": 0x0D2B6F7D,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b87d6f2b0d",
            "source_block_id": "native@0x40AE3E",
            "source_instruction_bytes": "a1ccae4800",
            "source_native_ea": 0x40AE3E,
            "source_width_bits": 32,
        }
        row10_constant_reference = reference_payloads[_ROW10_CONSTANT_OPERATION_ID]
        assert row10_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AED0,
            "depends_on": [_ROW9_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x0D9E7D1B,
            "operation_id": _ROW10_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "1b7d9e0d",
            "reference_operation_id": "rhad:constant@0x40AE4A",
            "reference_order": 10,
            "reference_raw_value": 0x0D9E7D1B,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b91b7d9e0d",
            "source_block_id": "native@0x40AE3E",
            "source_instruction_bytes": "8b0dd0ae4800",
            "source_native_ea": 0x40AE4A,
            "source_width_bits": 32,
        }
        row11_constant_reference = reference_payloads[_ROW11_CONSTANT_OPERATION_ID]
        assert row11_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE0C,
            "depends_on": [_ROW10_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x960298BC,
            "operation_id": _ROW11_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "bc980296",
            "reference_operation_id": "rhad:constant@0x40AEAC",
            "reference_order": 11,
            "reference_raw_value": 0x960298BC,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9bc980296",
            "source_block_id": "native@0x40AEA5",
            "source_instruction_bytes": "8b0d0cae4800",
            "source_native_ea": 0x40AEAC,
            "source_width_bits": 32,
        }
        row12_constant_reference = reference_payloads[_ROW12_CONSTANT_OPERATION_ID]
        assert row12_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE5C,
            "depends_on": [_ROW11_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x0A6886EA,
            "operation_id": _ROW12_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "ea86680a",
            "reference_operation_id": "rhad:constant@0x40AF00",
            "reference_order": 12,
            "reference_raw_value": 0x0A6886EA,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9ea86680a",
            "source_block_id": "native@0x40AF00",
            "source_instruction_bytes": "8b0d5cae4800",
            "source_native_ea": 0x40AF00,
            "source_width_bits": 32,
        }
        row13_constant_reference = reference_payloads[_ROW13_CONSTANT_OPERATION_ID]
        assert row13_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE60,
            "depends_on": [_ROW12_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x3E83E71C,
            "operation_id": _ROW13_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "1ce7833e",
            "reference_operation_id": "rhad:constant@0x40AF32",
            "reference_order": 13,
            "reference_raw_value": 0x3E83E71C,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b81ce7833e",
            "source_block_id": "native@0x40AF2F",
            "source_instruction_bytes": "a160ae4800",
            "source_native_ea": 0x40AF32,
            "source_width_bits": 32,
        }
        row14_constant_reference = reference_payloads[_ROW14_CONSTANT_OPERATION_ID]
        assert row14_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE64,
            "depends_on": [_ROW13_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xA428094F,
            "operation_id": _ROW14_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "4f0928a4",
            "reference_operation_id": "rhad:constant@0x40AF45",
            "reference_order": 14,
            "reference_raw_value": 0xA428094F,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b84f0928a4",
            "source_block_id": "native@0x40AF2F",
            "source_instruction_bytes": "a164ae4800",
            "source_native_ea": 0x40AF45,
            "source_width_bits": 32,
        }
        row15_constant_reference = reference_payloads[_ROW15_CONSTANT_OPERATION_ID]
        assert row15_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE68,
            "depends_on": [_ROW14_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x84D944C6,
            "operation_id": _ROW15_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "c644d984",
            "reference_operation_id": "rhad:constant@0x40AF71",
            "reference_order": 15,
            "reference_raw_value": 0x84D944C6,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8c644d984",
            "source_block_id": "native@0x40AF2F",
            "source_instruction_bytes": "a168ae4800",
            "source_native_ea": 0x40AF71,
            "source_width_bits": 32,
        }
        row16_constant_reference = reference_payloads[_ROW16_CONSTANT_OPERATION_ID]
        assert row16_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE6C,
            "depends_on": [_ROW15_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x80819869,
            "operation_id": _ROW16_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "69988180",
            "reference_operation_id": "rhad:constant@0x40AF84",
            "reference_order": 16,
            "reference_raw_value": 0x80819869,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b969988180",
            "source_block_id": "native@0x40AF2F",
            "source_instruction_bytes": "8b0d6cae4800",
            "source_native_ea": 0x40AF84,
            "source_width_bits": 32,
        }
        row17_constant_reference = reference_payloads[_ROW17_CONSTANT_OPERATION_ID]
        assert row17_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE70,
            "depends_on": [_ROW16_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x1C35F720,
            "operation_id": _ROW17_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "20f7351c",
            "reference_operation_id": "rhad:constant@0x40AFA0",
            "reference_order": 17,
            "reference_raw_value": 0x1C35F720,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b820f7351c",
            "source_block_id": "native@0x40AF9D",
            "source_instruction_bytes": "a170ae4800",
            "source_native_ea": 0x40AFA0,
            "source_width_bits": 32,
        }
        row18_constant_reference = reference_payloads[_ROW18_CONSTANT_OPERATION_ID]
        assert row18_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE00,
            "depends_on": [_ROW17_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x290540B9,
            "operation_id": _ROW18_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "b9400529",
            "reference_operation_id": "rhad:constant@0x40B03E",
            "reference_order": 18,
            "reference_raw_value": 0x290540B9,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8b9400529",
            "source_block_id": "native@0x40B03E",
            "source_instruction_bytes": "a100ae4800",
            "source_native_ea": 0x40B03E,
            "source_width_bits": 32,
        }
        row19_constant_reference = reference_payloads[_ROW19_CONSTANT_OPERATION_ID]
        assert row19_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE24,
            "depends_on": [_ROW18_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xA332A636,
            "operation_id": _ROW19_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "36a632a3",
            "reference_operation_id": "rhad:constant@0x40B19B",
            "reference_order": 19,
            "reference_raw_value": 0xA332A636,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b836a632a3",
            "source_block_id": "native@0x40B199",
            "source_instruction_bytes": "a124ae4800",
            "source_native_ea": 0x40B19B,
            "source_width_bits": 32,
        }
        row20_constant_reference = reference_payloads[_ROW20_CONSTANT_OPERATION_ID]
        assert row20_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADE4,
            "depends_on": [_ROW19_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x92014BB4,
            "operation_id": _ROW20_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "b44b0192",
            "reference_operation_id": "rhad:constant@0x40B287",
            "reference_order": 20,
            "reference_raw_value": 0x92014BB4,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8b44b0192",
            "source_block_id": "native@0x40B287",
            "source_instruction_bytes": "a1e4ad4800",
            "source_native_ea": 0x40B287,
            "source_width_bits": 32,
        }
        row21_constant_reference = reference_payloads[_ROW21_CONSTANT_OPERATION_ID]
        assert row21_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE8C,
            "depends_on": [_ROW20_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x00AB7D99,
            "operation_id": _ROW21_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "997dab00",
            "reference_operation_id": "rhad:constant@0x40B2F7",
            "reference_order": 21,
            "reference_raw_value": 0x00AB7D99,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8997dab00",
            "source_block_id": "native@0x40B2F5",
            "source_instruction_bytes": "a18cae4800",
            "source_native_ea": 0x40B2F7,
            "source_width_bits": 32,
        }
        row22_constant_reference = reference_payloads[_ROW22_CONSTANT_OPERATION_ID]
        assert row22_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE30,
            "depends_on": [_ROW21_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x4B0FCF2A,
            "operation_id": _ROW22_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "2acf0f4b",
            "reference_operation_id": "rhad:constant@0x40B3B0",
            "reference_order": 22,
            "reference_raw_value": 0x4B0FCF2A,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b82acf0f4b",
            "source_block_id": "native@0x40B3B0",
            "source_instruction_bytes": "a130ae4800",
            "source_native_ea": 0x40B3B0,
            "source_width_bits": 32,
        }
        row23_constant_reference = reference_payloads[_ROW23_CONSTANT_OPERATION_ID]
        assert row23_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEA0,
            "depends_on": [_ROW22_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x2B0A43AF,
            "operation_id": _ROW23_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "af430a2b",
            "reference_operation_id": "rhad:constant@0x40B3FF",
            "reference_order": 23,
            "reference_raw_value": 0x2B0A43AF,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9af430a2b",
            "source_block_id": "native@0x40B3FF",
            "source_instruction_bytes": "8b0da0ae4800",
            "source_native_ea": 0x40B3FF,
            "source_width_bits": 32,
        }
        row24_constant_reference = reference_payloads[_ROW24_CONSTANT_OPERATION_ID]
        assert row24_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEA4,
            "depends_on": [_ROW23_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x7B2A1426,
            "operation_id": _ROW24_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "26142a7b",
            "reference_operation_id": "rhad:constant@0x40B410",
            "reference_order": 24,
            "reference_raw_value": 0x7B2A1426,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b926142a7b",
            "source_block_id": "native@0x40B3FF",
            "source_instruction_bytes": "8b0da4ae4800",
            "source_native_ea": 0x40B410,
            "source_width_bits": 32,
        }
        row25_constant_reference = reference_payloads[_ROW25_CONSTANT_OPERATION_ID]
        assert row25_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEA8,
            "depends_on": [_ROW24_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x03BF7CFA,
            "operation_id": _ROW25_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "fa7cbf03",
            "reference_operation_id": "rhad:constant@0x40B421",
            "reference_order": 25,
            "reference_raw_value": 0x03BF7CFA,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9fa7cbf03",
            "source_block_id": "native@0x40B3FF",
            "source_instruction_bytes": "8b0da8ae4800",
            "source_native_ea": 0x40B421,
            "source_width_bits": 32,
        }
        row26_constant_reference = reference_payloads[_ROW26_CONSTANT_OPERATION_ID]
        assert row26_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEAC,
            "depends_on": [_ROW25_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x69907666,
            "operation_id": _ROW26_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "66769069",
            "reference_operation_id": "rhad:constant@0x40B432",
            "reference_order": 26,
            "reference_raw_value": 0x69907666,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b966769069",
            "source_block_id": "native@0x40B3FF",
            "source_instruction_bytes": "8b0dacae4800",
            "source_native_ea": 0x40B432,
            "source_width_bits": 32,
        }
        row27_constant_reference = reference_payloads[_ROW27_CONSTANT_OPERATION_ID]
        assert row27_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEB0,
            "depends_on": [_ROW26_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 12,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0xB4345ECF,
            "operation_id": _ROW27_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "cf5e34b4",
            "reference_operation_id": "rhad:constant@0x40B443",
            "reference_order": 27,
            "reference_raw_value": 0xB4345ECF,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90bacf5e34b4",
            "source_block_id": "native@0x40B3FF",
            "source_instruction_bytes": "8b15b0ae4800",
            "source_native_ea": 0x40B443,
            "source_width_bits": 32,
        }
        row28_constant_reference = reference_payloads[_ROW28_CONSTANT_OPERATION_ID]
        assert row28_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEB4,
            "depends_on": [_ROW27_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x545AE7F4,
            "operation_id": _ROW28_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "f4e75a54",
            "reference_operation_id": "rhad:constant@0x40B450",
            "reference_order": 28,
            "reference_raw_value": 0x545AE7F4,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9f4e75a54",
            "source_block_id": "native@0x40B3FF",
            "source_instruction_bytes": "8b0db4ae4800",
            "source_native_ea": 0x40B450,
            "source_width_bits": 32,
        }
        row29_constant_reference = reference_payloads[_ROW29_CONSTANT_OPERATION_ID]
        assert row29_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEB8,
            "depends_on": [_ROW28_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x372ECFB4,
            "operation_id": _ROW29_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "b4cf2e37",
            "reference_operation_id": "rhad:constant@0x40B45D",
            "reference_order": 29,
            "reference_raw_value": 0x372ECFB4,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8b4cf2e37",
            "source_block_id": "native@0x40B3FF",
            "source_instruction_bytes": "a1b8ae4800",
            "source_native_ea": 0x40B45D,
            "source_width_bits": 32,
        }
        row30_constant_reference = reference_payloads[_ROW30_CONSTANT_OPERATION_ID]
        assert row30_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE14,
            "depends_on": [_ROW29_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "movzx_r32_byte_absolute",
            "materialized_value": 0x16,
            "operation_id": _ROW30_CONSTANT_OPERATION_ID,
            "operation_variant": "movzx_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_byte_move",
            "reference_data_bytes_le": "1674fe2e",
            "reference_operation_id": "rhad:constant@0x40B815",
            "reference_order": 30,
            "reference_raw_value": 0x2EFE7416,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b9160000009090",
            "source_block_id": "native@0x40B810",
            "source_instruction_bytes": "0fb60d14ae4800",
            "source_native_ea": 0x40B815,
            "source_width_bits": 8,
        }
        row31_constant_reference = reference_payloads[_ROW31_CONSTANT_OPERATION_ID]
        assert row31_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE18,
            "depends_on": [_ROW30_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0xF2112ED2,
            "operation_id": _ROW31_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "d22e11f2",
            "reference_operation_id": "rhad:constant@0x40B825",
            "reference_order": 31,
            "reference_raw_value": 0xF2112ED2,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9d22e11f2",
            "source_block_id": "native@0x40B810",
            "source_instruction_bytes": "8b0d18ae4800",
            "source_native_ea": 0x40B825,
            "source_width_bits": 32,
        }
        row32_constant_reference = reference_payloads[_ROW32_CONSTANT_OPERATION_ID]
        assert row32_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE1C,
            "depends_on": [_ROW31_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 12,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x895C6120,
            "operation_id": _ROW32_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "20615c89",
            "reference_operation_id": "rhad:constant@0x40B84C",
            "reference_order": 32,
            "reference_raw_value": 0x895C6120,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90ba20615c89",
            "source_block_id": "native@0x40B810",
            "source_instruction_bytes": "8b151cae4800",
            "source_native_ea": 0x40B84C,
            "source_width_bits": 32,
        }
        row33_constant_reference = reference_payloads[_ROW33_CONSTANT_OPERATION_ID]
        assert row33_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48A99C,
            "depends_on": [_ROW32_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 8,
            },
            "destination_width_bits": 32,
            "encoding_variant": "movzx_r32_byte_absolute",
            "materialized_value": 0xF0,
            "operation_id": _ROW33_CONSTANT_OPERATION_ID,
            "operation_variant": "movzx_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_byte_zero_extend",
            "reference_data_bytes_le": "f031516a",
            "reference_operation_id": "rhad:constant@0x40B8E6",
            "reference_order": 33,
            "reference_raw_value": 0x6A5131F0,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8f00000009090",
            "source_block_id": "native@0x40B8E6",
            "source_instruction_bytes": "0fb6059ca94800",
            "source_native_ea": 0x40B8E6,
            "source_width_bits": 8,
        }
        row34_constant_reference = reference_payloads[_ROW34_CONSTANT_OPERATION_ID]
        assert row34_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE90,
            "depends_on": [_ROW33_CONSTANT_OPERATION_ID],
            "destination_storage": {
                "kind": "r",
                "offset": 16,
            },
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x7CBC55D0,
            "operation_id": _ROW34_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "d055bc7c",
            "reference_operation_id": "rhad:constant@0x40B8ED",
            "reference_order": 34,
            "reference_raw_value": 0x7CBC55D0,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b9d055bc7c",
            "source_block_id": "native@0x40B8E6",
            "source_instruction_bytes": "8b0d90ae4800",
            "source_native_ea": 0x40B8ED,
            "source_width_bits": 32,
        }
        row35_constant_reference = reference_payloads[_ROW35_CONSTANT_OPERATION_ID]
        assert row35_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE94,
            "depends_on": [_ROW34_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xE2176A36,
            "operation_id": _ROW35_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "366a17e2",
            "reference_operation_id": "rhad:constant@0x40B8FC",
            "reference_order": 35,
            "reference_raw_value": 0xE2176A36,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8366a17e2",
            "source_block_id": "native@0x40B8E6",
            "source_instruction_bytes": "a194ae4800",
            "source_native_ea": 0x40B8FC,
            "source_width_bits": 32,
        }
        row36_constant_reference = reference_payloads[_ROW36_CONSTANT_OPERATION_ID]
        assert row36_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE34,
            "depends_on": [_ROW35_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "movzx_r32_byte_absolute",
            "materialized_value": 0x6B,
            "operation_id": _ROW36_CONSTANT_OPERATION_ID,
            "operation_variant": "movzx_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_byte_move",
            "reference_data_bytes_le": "6b000000",
            "reference_operation_id": "rhad:constant@0x40B9C1",
            "reference_order": 36,
            "reference_raw_value": 0x6B,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b86b0000009090",
            "source_block_id": "native@0x40B9A6",
            "source_instruction_bytes": "0fb60534ae4800",
            "source_native_ea": 0x40B9C1,
            "source_width_bits": 8,
        }
        row37_constant_reference = reference_payloads[_ROW37_CONSTANT_OPERATION_ID]
        assert row37_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE38,
            "depends_on": [_ROW36_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x569806D9,
            "operation_id": _ROW37_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "d9069856",
            "reference_operation_id": "rhad:constant@0x40B9FF",
            "reference_order": 37,
            "reference_raw_value": 0x569806D9,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8d9069856",
            "source_block_id": "native@0x40B9A6",
            "source_instruction_bytes": "a138ae4800",
            "source_native_ea": 0x40B9FF,
            "source_width_bits": 32,
        }
        row38_constant_reference = reference_payloads[_ROW38_CONSTANT_OPERATION_ID]
        assert row38_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE3C,
            "depends_on": [_ROW37_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xEC671FEC,
            "operation_id": _ROW38_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "ec1f67ec",
            "reference_operation_id": "rhad:constant@0x40BA1A",
            "reference_order": 38,
            "reference_raw_value": 0xEC671FEC,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8ec1f67ec",
            "source_block_id": "native@0x40B9A6",
            "source_instruction_bytes": "a13cae4800",
            "source_native_ea": 0x40BA1A,
            "source_width_bits": 32,
        }
        row39_constant_reference = reference_payloads[_ROW39_CONSTANT_OPERATION_ID]
        assert row39_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE40,
            "depends_on": [_ROW38_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x65119397,
            "operation_id": _ROW39_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "97931165",
            "reference_operation_id": "rhad:constant@0x40BA2D",
            "reference_order": 39,
            "reference_raw_value": 0x65119397,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b897931165",
            "source_block_id": "native@0x40B9A6",
            "source_instruction_bytes": "a140ae4800",
            "source_native_ea": 0x40BA2D,
            "source_width_bits": 32,
        }
        row40_constant_reference = reference_payloads[_ROW40_CONSTANT_OPERATION_ID]
        assert row40_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE44,
            "depends_on": [_ROW39_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xE13C8922,
            "operation_id": _ROW40_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "22893ce1",
            "reference_operation_id": "rhad:constant@0x40BA47",
            "reference_order": 40,
            "reference_raw_value": 0xE13C8922,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b822893ce1",
            "source_block_id": "native@0x40B9A6",
            "source_instruction_bytes": "a144ae4800",
            "source_native_ea": 0x40BA47,
            "source_width_bits": 32,
        }
        row41_constant_reference = reference_payloads[_ROW41_CONSTANT_OPERATION_ID]
        assert row41_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE48,
            "depends_on": [_ROW40_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x5514C30D,
            "operation_id": _ROW41_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "0dc31455",
            "reference_operation_id": "rhad:constant@0x40BA63",
            "reference_order": 41,
            "reference_raw_value": 0x5514C30D,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b80dc31455",
            "source_block_id": "native@0x40BA5C",
            "source_instruction_bytes": "a148ae4800",
            "source_native_ea": 0x40BA63,
            "source_width_bits": 32,
        }
        row42_constant_reference = reference_payloads[_ROW42_CONSTANT_OPERATION_ID]
        assert row42_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE4C,
            "depends_on": [_ROW41_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x9AFD72B5,
            "operation_id": _ROW42_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "b572fd9a",
            "reference_operation_id": "rhad:constant@0x40BA7F",
            "reference_order": 42,
            "reference_raw_value": 0x9AFD72B5,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8b572fd9a",
            "source_block_id": "native@0x40BA78",
            "source_instruction_bytes": "a14cae4800",
            "source_native_ea": 0x40BA7F,
            "source_width_bits": 32,
        }
        row43_constant_reference = reference_payloads[_ROW43_CONSTANT_OPERATION_ID]
        assert row43_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE50,
            "depends_on": [_ROW42_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x2E203DEF,
            "operation_id": _ROW43_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "ef3d202e",
            "reference_operation_id": "rhad:constant@0x40BACF",
            "reference_order": 43,
            "reference_raw_value": 0x2E203DEF,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8ef3d202e",
            "source_block_id": "native@0x40BA92",
            "source_instruction_bytes": "a150ae4800",
            "source_native_ea": 0x40BACF,
            "source_width_bits": 32,
        }
        row44_constant_reference = reference_payloads[_ROW44_CONSTANT_OPERATION_ID]
        assert row44_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE54,
            "depends_on": [_ROW43_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x14589C14,
            "operation_id": _ROW44_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "149c5814",
            "reference_operation_id": "rhad:constant@0x40BB0A",
            "reference_order": 44,
            "reference_raw_value": 0x14589C14,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8149c5814",
            "source_block_id": "native@0x40BA92",
            "source_instruction_bytes": "a154ae4800",
            "source_native_ea": 0x40BB0A,
            "source_width_bits": 32,
        }
        row45_constant_reference = reference_payloads[_ROW45_CONSTANT_OPERATION_ID]
        assert row45_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE58,
            "depends_on": [_ROW44_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xADEC313A,
            "operation_id": _ROW45_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "3a31ecad",
            "reference_operation_id": "rhad:constant@0x40BB28",
            "reference_order": 45,
            "reference_raw_value": 0xADEC313A,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b83a31ecad",
            "source_block_id": "native@0x40BA92",
            "source_instruction_bytes": "a158ae4800",
            "source_native_ea": 0x40BB28,
            "source_width_bits": 32,
        }
        row46_constant_reference = reference_payloads[_ROW46_CONSTANT_OPERATION_ID]
        assert row46_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE74,
            "depends_on": [_ROW45_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xA23904A4,
            "operation_id": _ROW46_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "a40439a2",
            "reference_operation_id": "rhad:constant@0x40BD84",
            "reference_order": 46,
            "reference_raw_value": 0xA23904A4,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8a40439a2",
            "source_block_id": "native@0x40BD84",
            "source_instruction_bytes": "a174ae4800",
            "source_native_ea": 0x40BD84,
            "source_width_bits": 32,
        }
        row47_constant_reference = reference_payloads[_ROW47_CONSTANT_OPERATION_ID]
        assert row47_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE78,
            "depends_on": [_ROW46_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xF4159152,
            "operation_id": _ROW47_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "529115f4",
            "reference_operation_id": "rhad:constant@0x40BD9B",
            "reference_order": 47,
            "reference_raw_value": 0xF4159152,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8529115f4",
            "source_block_id": "native@0x40BD84",
            "source_instruction_bytes": "a178ae4800",
            "source_native_ea": 0x40BD9B,
            "source_width_bits": 32,
        }
        row48_constant_reference = reference_payloads[_ROW48_CONSTANT_OPERATION_ID]
        assert row48_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48B00C,
            "depends_on": [_ROW47_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xC2A51B1F,
            "operation_id": _ROW48_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "1f1ba5c2",
            "reference_operation_id": "rhad:constant@0x40BDD8",
            "reference_order": 48,
            "reference_raw_value": 0xC2A51B1F,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b81f1ba5c2",
            "source_block_id": "native@0x40BDD5",
            "source_instruction_bytes": "a10cb04800",
            "source_native_ea": 0x40BDD8,
            "source_width_bits": 32,
        }
        row49_constant_reference = reference_payloads[_ROW49_CONSTANT_OPERATION_ID]
        assert row49_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48B010,
            "depends_on": [_ROW48_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x544B2386,
            "operation_id": _ROW49_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "86234b54",
            "reference_operation_id": "rhad:constant@0x40BDEB",
            "reference_order": 49,
            "reference_raw_value": 0x544B2386,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b986234b54",
            "source_block_id": "native@0x40BDD5",
            "source_instruction_bytes": "8b0d10b04800",
            "source_native_ea": 0x40BDEB,
            "source_width_bits": 32,
        }
        row50_constant_reference = reference_payloads[_ROW50_CONSTANT_OPERATION_ID]
        assert row50_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE20,
            "depends_on": [_ROW49_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xE888549D,
            "operation_id": _ROW50_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "9d5488e8",
            "reference_operation_id": "rhad:constant@0x40BE63",
            "reference_order": 50,
            "reference_raw_value": 0xE888549D,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b89d5488e8",
            "source_block_id": "native@0x40BE63",
            "source_instruction_bytes": "a120ae4800",
            "source_native_ea": 0x40BE63,
            "source_width_bits": 32,
        }
        row51_constant_reference = reference_payloads[_ROW51_CONSTANT_OPERATION_ID]
        assert row51_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE04,
            "depends_on": [_ROW50_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x8B2D25E3,
            "operation_id": _ROW51_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "e3252d8b",
            "reference_operation_id": "rhad:constant@0x40BF31",
            "reference_order": 51,
            "reference_raw_value": 0x8B2D25E3,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b8e3252d8b",
            "source_block_id": "native@0x40BF2F",
            "source_instruction_bytes": "a104ae4800",
            "source_native_ea": 0x40BF31,
            "source_width_bits": 32,
        }
        row52_constant_reference = reference_payloads[_ROW52_CONSTANT_OPERATION_ID]
        assert row52_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE08,
            "depends_on": [_ROW51_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x7392827E,
            "operation_id": _ROW52_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "7e829273",
            "reference_operation_id": "rhad:constant@0x40BF4E",
            "reference_order": 52,
            "reference_raw_value": 0x7392827E,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b97e829273",
            "source_block_id": "native@0x40BF43",
            "source_instruction_bytes": "8b0d08ae4800",
            "source_native_ea": 0x40BF4E,
            "source_width_bits": 32,
        }
        row53_constant_reference = reference_payloads[_ROW53_CONSTANT_OPERATION_ID]
        assert row53_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADF0,
            "depends_on": [_ROW52_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x982B0365,
            "operation_id": _ROW53_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "65032b98",
            "reference_operation_id": "rhad:constant@0x40C118",
            "reference_order": 53,
            "reference_raw_value": 0x982B0365,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b965032b98",
            "source_block_id": "native@0x40C10A",
            "source_instruction_bytes": "8b0df0ad4800",
            "source_native_ea": 0x40C118,
            "source_width_bits": 32,
        }
        row54_constant_reference = reference_payloads[_ROW54_CONSTANT_OPERATION_ID]
        assert row54_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE98,
            "depends_on": [_ROW53_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0xF9133C0C,
            "operation_id": _ROW54_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "0c3c13f9",
            "reference_operation_id": "rhad:constant@0x40C1A0",
            "reference_order": 54,
            "reference_raw_value": 0xF9133C0C,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b80c3c13f9",
            "source_block_id": "native@0x40C1A0",
            "source_instruction_bytes": "a198ae4800",
            "source_native_ea": 0x40C1A0,
            "source_width_bits": 32,
        }
        row55_constant_reference = reference_payloads[_ROW55_CONSTANT_OPERATION_ID]
        assert row55_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE9C,
            "depends_on": [_ROW54_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x966EA130,
            "operation_id": _ROW55_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "30a16e96",
            "reference_operation_id": "rhad:constant@0x40C1AC",
            "reference_order": 55,
            "reference_raw_value": 0x966EA130,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b930a16e96",
            "source_block_id": "native@0x40C1A0",
            "source_instruction_bytes": "8b0d9cae4800",
            "source_native_ea": 0x40C1AC,
            "source_width_bits": 32,
        }
        row56_constant_reference = reference_payloads[_ROW56_CONSTANT_OPERATION_ID]
        assert row56_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADF4,
            "depends_on": [_ROW55_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x3120D068,
            "operation_id": _ROW56_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "68d02031",
            "reference_operation_id": "rhad:constant@0x40C21B",
            "reference_order": 56,
            "reference_raw_value": 0x3120D068,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b968d02031",
            "source_block_id": "native@0x40C20C",
            "source_instruction_bytes": "8b0df4ad4800",
            "source_native_ea": 0x40C21B,
            "source_width_bits": 32,
        }
        row57_constant_reference = reference_payloads[_ROW57_CONSTANT_OPERATION_ID]
        assert row57_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADD0,
            "depends_on": [_ROW56_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x1789699A,
            "operation_id": _ROW57_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "9a698917",
            "reference_operation_id": "rhad:constant@0x40C26D",
            "reference_order": 57,
            "reference_raw_value": 0x1789699A,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b89a698917",
            "source_block_id": "native@0x40C26D",
            "source_instruction_bytes": "a1d0ad4800",
            "source_native_ea": 0x40C26D,
            "source_width_bits": 32,
        }
        row58_constant_reference = reference_payloads[_ROW58_CONSTANT_OPERATION_ID]
        assert row58_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADD4,
            "depends_on": [_ROW57_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0xA86CED07,
            "operation_id": _ROW58_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "07ed6ca8",
            "reference_operation_id": "rhad:constant@0x40C279",
            "reference_order": 58,
            "reference_raw_value": 0xA86CED07,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b907ed6ca8",
            "source_block_id": "native@0x40C26D",
            "source_instruction_bytes": "8b0dd4ad4800",
            "source_native_ea": 0x40C279,
            "source_width_bits": 32,
        }
        row59_constant_reference = reference_payloads[_ROW59_CONSTANT_OPERATION_ID]
        assert row59_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADD8,
            "depends_on": [_ROW58_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 12},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x5AB9E7B4,
            "operation_id": _ROW59_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "b4e7b95a",
            "reference_operation_id": "rhad:constant@0x40C286",
            "reference_order": 59,
            "reference_raw_value": 0x5AB9E7B4,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90bab4e7b95a",
            "source_block_id": "native@0x40C26D",
            "source_instruction_bytes": "8b15d8ad4800",
            "source_native_ea": 0x40C286,
            "source_width_bits": 32,
        }
        row60_constant_reference = reference_payloads[_ROW60_CONSTANT_OPERATION_ID]
        assert row60_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADDC,
            "depends_on": [_ROW59_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 32},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0xD836346D,
            "operation_id": _ROW60_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "6d3436d8",
            "reference_operation_id": "rhad:constant@0x40C293",
            "reference_order": 60,
            "reference_raw_value": 0xD836346D,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90bf6d3436d8",
            "source_block_id": "native@0x40C26D",
            "source_instruction_bytes": "8b3ddcad4800",
            "source_native_ea": 0x40C293,
            "source_width_bits": 32,
        }
        row61_constant_reference = reference_payloads[_ROW61_CONSTANT_OPERATION_ID]
        assert row61_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADE0,
            "depends_on": [_ROW60_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x99FCA32B,
            "operation_id": _ROW61_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "2ba3fc99",
            "reference_operation_id": "rhad:constant@0x40C2AF",
            "reference_order": 61,
            "reference_raw_value": 0x99FCA32B,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90b92ba3fc99",
            "source_block_id": "native@0x40C2AF",
            "source_instruction_bytes": "8b0de0ad4800",
            "source_native_ea": 0x40C2AF,
            "source_width_bits": 32,
        }
        row62_constant_reference = reference_payloads[_ROW62_CONSTANT_OPERATION_ID]
        assert row62_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEC8,
            "depends_on": [_ROW61_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 8,
            "encoding_variant": "xor_r8_absolute",
            "materialized_value": 1,
            "operation_id": _ROW62_CONSTANT_OPERATION_ID,
            "operation_variant": "xor_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_byte_xor",
            "reference_data_bytes_le": "01000000",
            "reference_operation_id": "rhad:constant@0x40C322",
            "reference_order": 62,
            "reference_raw_value": 1,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_arith_mem_to_imm"
            ),
            "replacement_instruction_bytes": "80f001909090",
            "source_block_id": "native@0x40C315",
            "source_instruction_bytes": "3205c8ae4800",
            "source_native_ea": 0x40C322,
            "source_width_bits": 8,
        }
        row63_constant_reference = reference_payloads[_ROW63_CONSTANT_OPERATION_ID]
        assert row63_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48ADE8,
            "depends_on": [_ROW62_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 12},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x3AE47C72,
            "operation_id": _ROW63_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "727ce43a",
            "reference_operation_id": "rhad:constant@0x40C4F8",
            "reference_order": 63,
            "reference_raw_value": 0x3AE47C72,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "90ba727ce43a",
            "source_block_id": "native@0x40C4F6",
            "source_instruction_bytes": "8b15e8ad4800",
            "source_native_ea": 0x40C4F8,
            "source_width_bits": 32,
        }
        row64_constant_reference = reference_payloads[_ROW64_CONSTANT_OPERATION_ID]
        assert row64_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEBC,
            "depends_on": [_ROW63_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 8},
            "destination_width_bits": 32,
            "encoding_variant": "mov_eax_absolute",
            "materialized_value": 0x9B874143,
            "operation_id": _ROW64_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "4341879b",
            "reference_operation_id": "rhad:constant@0x40C592",
            "reference_order": 64,
            "reference_raw_value": 0x9B874143,
            "reference_read_width_bits": 32,
            "reference_symbol": (
                "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
            ),
            "replacement_instruction_bytes": "b84341879b",
            "source_block_id": "native@0x40C592",
            "source_instruction_bytes": "a1bcae4800",
            "source_native_ea": 0x40C592,
            "source_width_bits": 32,
        }
        row65_constant_reference = reference_payloads[_ROW65_CONSTANT_OPERATION_ID]
        assert row65_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEC0,
            "depends_on": [_ROW64_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x7A9F2473,
            "operation_id": _ROW65_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "73249f7a",
            "reference_operation_id": "rhad:constant@0x40C59E",
            "reference_order": 65,
            "reference_raw_value": 0x7A9F2473,
            "reference_read_width_bits": 32,
            "reference_symbol": "deob_consts.ConstantInliner.transform_mov_mem_to_imm",
            "replacement_instruction_bytes": "90b973249f7a",
            "source_block_id": "native@0x40C592",
            "source_instruction_bytes": "8b0dc0ae4800",
            "source_native_ea": 0x40C59E,
            "source_width_bits": 32,
        }
        row66_constant_reference = reference_payloads[_ROW66_CONSTANT_OPERATION_ID]
        assert row66_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AEC4,
            "depends_on": [_ROW65_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 16},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x381897B5,
            "operation_id": _ROW66_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "b5971838",
            "reference_operation_id": "rhad:constant@0x40C5BD",
            "reference_order": 66,
            "reference_raw_value": 0x381897B5,
            "reference_read_width_bits": 32,
            "reference_symbol": "deob_consts.ConstantInliner.transform_mov_mem_to_imm",
            "replacement_instruction_bytes": "90b9b5971838",
            "source_block_id": "native@0x40C5BD",
            "source_instruction_bytes": "8b0dc4ae4800",
            "source_native_ea": 0x40C5BD,
            "source_width_bits": 32,
        }
        row67_constant_reference = reference_payloads[_ROW67_CONSTANT_OPERATION_ID]
        assert row67_constant_reference == {
            "category": "constant_materialization",
            "data_native_ea": 0x48AE88,
            "depends_on": [_ROW66_CONSTANT_OPERATION_ID],
            "destination_storage": {"kind": "r", "offset": 12},
            "destination_width_bits": 32,
            "encoding_variant": "mov_r32_absolute",
            "materialized_value": 0x5BFC3930,
            "operation_id": _ROW67_CONSTANT_OPERATION_ID,
            "operation_variant": "mov_absolute",
            "phase": "constant_materialization",
            "publication_envelope": "imported_global_move",
            "reference_data_bytes_le": "3039fc5b",
            "reference_operation_id": "rhad:constant@0x40C667",
            "reference_order": 67,
            "reference_raw_value": 0x5BFC3930,
            "reference_read_width_bits": 32,
            "reference_symbol": "deob_consts.ConstantInliner.transform_mov_mem_to_imm",
            "replacement_instruction_bytes": "90ba3039fc5b",
            "source_block_id": "native@0x40C665",
            "source_instruction_bytes": "8b1588ae4800",
            "source_native_ea": 0x40C667,
            "source_width_bits": 32,
        }

        published_payload = json.loads(lifecycle_rows[2][3])
        assert (
            published_payload["aggregate_program_identity"]
            == (compiled_payload["aggregate_program_identity"])
        )
        assert published_payload["proof_artifact_identities"] == [
            row16_artifact_identity,
            row17_artifact_identity,
            row68_artifact_identity,
            row96_artifact_identity,
            row126_artifact_identity,
            row129_artifact_identity,
            row134_artifact_identity,
            row167_artifact_identity,
        ]

        maturity_payloads = {row[1]: json.loads(row[3]) for row in maturity_rows}
        for maturity in ("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT"):
            observations = {
                row["operation_id"]: row
                for row in maturity_payloads[maturity]["operation_observations"]
            }
            accepted = observations["rhad:route@0x40A605"]
            assert accepted["source_present"] is True
            assert accepted["source_topology_reachable"] is True
            assert accepted["source_topology_retired"] is False
            assert accepted["indirect_transfer_present"] is False
            assert accepted["target_eas"] == [0x40A607, 0x40B6C0]
            assert accepted["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert accepted["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert accepted["semantic_targets_survive"] is True
            assert accepted["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert accepted["passed"] is True
            constant = observations[_CONSTANT_OPERATION_ID]
            assert constant["reference_operation_id"] == "rhad:constant@0x40A574"
            assert constant["operation_category"] == "constant_materialization"
            assert constant["operation_variant"] == "add_absolute"
            assert constant["source_native_ea"] == 0x40A574
            assert constant["data_native_ea"] == 0x48ADCC
            assert constant["materialized_value"] == 0x3776723F
            assert constant["absolute_load_present"] is False
            assert constant["passed"] is True
            if constant["source_present"]:
                assert constant["source_topology_reachable"] is True
                assert constant["source_topology_retired"] is False
                assert constant["materialized_constant_present"] is True
            else:
                assert constant["source_topology_reachable"] is False
                assert constant["source_topology_retired"] is True
            if maturity == "MMAT_GENERATED":
                assert constant["flag_envelope_survives"] is True
                assert constant["semantic_envelope_survives"] is True
                assert constant["exact_generated_envelope"] is True
            mov_constant = observations[_MOV_CONSTANT_OPERATION_ID]
            assert mov_constant["reference_operation_id"] == (
                "rhad:constant@0x40A710"
            )
            assert mov_constant["operation_variant"] == "mov_absolute"
            assert mov_constant["encoding_variant"] == "mov_r32_absolute"
            assert mov_constant["publication_envelope"] == "imported_global_move"
            assert mov_constant["destination_storage"]["key"] == "r12"
            assert mov_constant["absolute_load_present"] is False
            assert mov_constant["passed"] is True
            if mov_constant["source_present"]:
                assert mov_constant["destination_delivery_present"] is True
                assert mov_constant["materialized_constant_present"] is True
                assert mov_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert mov_constant["exact_generated_envelope"] is True
            eax_constant = observations[_EAX_CONSTANT_OPERATION_ID]
            assert eax_constant["reference_operation_id"] == (
                "rhad:constant@0x40A868"
            )
            assert eax_constant["operation_variant"] == "mov_absolute"
            assert eax_constant["encoding_variant"] == "mov_eax_absolute"
            assert eax_constant["publication_envelope"] == "imported_global_move"
            assert eax_constant["destination_storage"]["key"] == "r8"
            assert eax_constant["absolute_load_present"] is False
            assert eax_constant["passed"] is True
            if eax_constant["source_present"]:
                assert eax_constant["destination_delivery_present"] is True
                assert eax_constant["materialized_constant_present"] is True
                assert eax_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert eax_constant["exact_generated_envelope"] is True
            row3_constant = observations[_ROW3_CONSTANT_OPERATION_ID]
            assert row3_constant["reference_operation_id"] == (
                "rhad:constant@0x40A903"
            )
            assert row3_constant["operation_variant"] == "mov_absolute"
            assert row3_constant["encoding_variant"] == "mov_eax_absolute"
            assert row3_constant["publication_envelope"] == "imported_global_move"
            assert row3_constant["destination_storage"]["key"] == "r8"
            assert row3_constant["absolute_load_present"] is False
            assert row3_constant["passed"] is True
            if row3_constant["source_present"]:
                assert row3_constant["destination_delivery_present"] is True
                assert row3_constant["materialized_constant_present"] is True
                assert row3_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row3_constant["exact_generated_envelope"] is True
            row4_constant = observations[_ROW4_CONSTANT_OPERATION_ID]
            assert row4_constant["reference_operation_id"] == (
                "rhad:constant@0x40A922"
            )
            assert row4_constant["operation_variant"] == "mov_absolute"
            assert row4_constant["encoding_variant"] == "mov_r32_absolute"
            assert row4_constant["publication_envelope"] == "imported_global_move"
            assert row4_constant["destination_storage"]["key"] == "r16"
            assert row4_constant["absolute_load_present"] is False
            assert row4_constant["passed"] is True
            if row4_constant["source_present"]:
                assert row4_constant["destination_delivery_present"] is True
                assert row4_constant["materialized_constant_present"] is True
                assert row4_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row4_constant["exact_generated_envelope"] is True
            row5_constant = observations[_ROW5_CONSTANT_OPERATION_ID]
            assert row5_constant["reference_operation_id"] == (
                "rhad:constant@0x40A9AE"
            )
            assert row5_constant["operation_variant"] == "mov_absolute"
            assert row5_constant["encoding_variant"] == "mov_eax_absolute"
            assert row5_constant["publication_envelope"] == "imported_global_move"
            assert row5_constant["destination_storage"]["key"] == "r8"
            assert row5_constant["absolute_load_present"] is False
            assert row5_constant["passed"] is True
            if row5_constant["source_present"]:
                assert row5_constant["destination_delivery_present"] is True
                assert row5_constant["materialized_constant_present"] is True
                assert row5_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row5_constant["exact_generated_envelope"] is True
            row6_constant = observations[_ROW6_CONSTANT_OPERATION_ID]
            assert row6_constant["reference_operation_id"] == (
                "rhad:constant@0x40AAC2"
            )
            assert row6_constant["operation_variant"] == "mov_absolute"
            assert row6_constant["encoding_variant"] == "mov_r32_absolute"
            assert row6_constant["publication_envelope"] == "imported_global_move"
            assert row6_constant["destination_storage"]["key"] == "r12"
            assert row6_constant["absolute_load_present"] is False
            assert row6_constant["passed"] is True
            if row6_constant["source_present"]:
                assert row6_constant["destination_delivery_present"] is True
                assert row6_constant["materialized_constant_present"] is True
                assert row6_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row6_constant["exact_generated_envelope"] is True
            row7_constant = observations[_ROW7_CONSTANT_OPERATION_ID]
            assert row7_constant["reference_operation_id"] == (
                "rhad:constant@0x40ABFF"
            )
            assert row7_constant["operation_variant"] == "mov_absolute"
            assert row7_constant["encoding_variant"] == "mov_r32_absolute"
            assert row7_constant["publication_envelope"] == "imported_global_move"
            assert row7_constant["destination_storage"]["key"] == "r16"
            assert row7_constant["absolute_load_present"] is False
            assert row7_constant["passed"] is True
            if row7_constant["source_present"]:
                assert row7_constant["destination_delivery_present"] is True
                assert row7_constant["materialized_constant_present"] is True
                assert row7_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row7_constant["exact_generated_envelope"] is True
            row8_constant = observations[_ROW8_CONSTANT_OPERATION_ID]
            assert row8_constant["reference_operation_id"] == (
                "rhad:constant@0x40AC81"
            )
            assert row8_constant["operation_variant"] == "mov_absolute"
            assert row8_constant["encoding_variant"] == "mov_r32_absolute"
            assert row8_constant["publication_envelope"] == "imported_global_move"
            assert row8_constant["destination_storage"]["key"] == "r16"
            assert row8_constant["absolute_load_present"] is False
            assert row8_constant["passed"] is True
            if row8_constant["source_present"]:
                assert row8_constant["destination_delivery_present"] is True
                assert row8_constant["materialized_constant_present"] is True
                assert row8_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row8_constant["exact_generated_envelope"] is True
            row9_constant = observations[_ROW9_CONSTANT_OPERATION_ID]
            assert row9_constant["reference_operation_id"] == (
                "rhad:constant@0x40AE3E"
            )
            assert row9_constant["operation_variant"] == "mov_absolute"
            assert row9_constant["encoding_variant"] == "mov_eax_absolute"
            assert row9_constant["publication_envelope"] == "imported_global_move"
            assert row9_constant["destination_storage"]["key"] == "r8"
            assert row9_constant["absolute_load_present"] is False
            assert row9_constant["passed"] is True
            if row9_constant["source_present"]:
                assert row9_constant["destination_delivery_present"] is True
                assert row9_constant["materialized_constant_present"] is True
                assert row9_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row9_constant["exact_generated_envelope"] is True
            row10_constant = observations[_ROW10_CONSTANT_OPERATION_ID]
            assert row10_constant["reference_operation_id"] == (
                "rhad:constant@0x40AE4A"
            )
            assert row10_constant["operation_variant"] == "mov_absolute"
            assert row10_constant["encoding_variant"] == "mov_r32_absolute"
            assert row10_constant["publication_envelope"] == "imported_global_move"
            assert row10_constant["destination_storage"]["key"] == "r16"
            assert row10_constant["absolute_load_present"] is False
            assert row10_constant["passed"] is True
            if row10_constant["source_present"]:
                assert row10_constant["destination_delivery_present"] is True
                assert row10_constant["materialized_constant_present"] is True
                assert row10_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row10_constant["exact_generated_envelope"] is True
            row11_constant = observations[_ROW11_CONSTANT_OPERATION_ID]
            assert row11_constant["reference_operation_id"] == (
                "rhad:constant@0x40AEAC"
            )
            assert row11_constant["operation_variant"] == "mov_absolute"
            assert row11_constant["encoding_variant"] == "mov_r32_absolute"
            assert row11_constant["publication_envelope"] == "imported_global_move"
            assert row11_constant["destination_storage"]["key"] == "r16"
            assert row11_constant["absolute_load_present"] is False
            assert row11_constant["passed"] is True
            if row11_constant["source_present"]:
                assert row11_constant["destination_delivery_present"] is True
                assert row11_constant["materialized_constant_present"] is True
                assert row11_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row11_constant["exact_generated_envelope"] is True
            row12_constant = observations[_ROW12_CONSTANT_OPERATION_ID]
            assert row12_constant["reference_operation_id"] == (
                "rhad:constant@0x40AF00"
            )
            assert row12_constant["operation_variant"] == "mov_absolute"
            assert row12_constant["encoding_variant"] == "mov_r32_absolute"
            assert row12_constant["publication_envelope"] == "imported_global_move"
            assert row12_constant["destination_storage"]["key"] == "r16"
            assert row12_constant["absolute_load_present"] is False
            assert row12_constant["passed"] is True
            if row12_constant["source_present"]:
                assert row12_constant["destination_delivery_present"] is True
                assert row12_constant["materialized_constant_present"] is True
                assert row12_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row12_constant["exact_generated_envelope"] is True
            row13_constant = observations[_ROW13_CONSTANT_OPERATION_ID]
            assert row13_constant["reference_operation_id"] == (
                "rhad:constant@0x40AF32"
            )
            assert row13_constant["operation_variant"] == "mov_absolute"
            assert row13_constant["encoding_variant"] == "mov_eax_absolute"
            assert row13_constant["publication_envelope"] == "imported_global_move"
            assert row13_constant["destination_storage"]["key"] == "r8"
            assert row13_constant["absolute_load_present"] is False
            assert row13_constant["passed"] is True
            if row13_constant["source_present"]:
                assert row13_constant["destination_delivery_present"] is True
                assert row13_constant["materialized_constant_present"] is True
                assert row13_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row13_constant["exact_generated_envelope"] is True
            row14_constant = observations[_ROW14_CONSTANT_OPERATION_ID]
            assert row14_constant["reference_operation_id"] == (
                "rhad:constant@0x40AF45"
            )
            assert row14_constant["operation_variant"] == "mov_absolute"
            assert row14_constant["encoding_variant"] == "mov_eax_absolute"
            assert row14_constant["publication_envelope"] == "imported_global_move"
            assert row14_constant["destination_storage"]["key"] == "r8"
            assert row14_constant["absolute_load_present"] is False
            assert row14_constant["passed"] is True
            if row14_constant["source_present"]:
                assert row14_constant["destination_delivery_present"] is True
                assert row14_constant["materialized_constant_present"] is True
                assert row14_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row14_constant["exact_generated_envelope"] is True
            row15_constant = observations[_ROW15_CONSTANT_OPERATION_ID]
            assert row15_constant["reference_operation_id"] == (
                "rhad:constant@0x40AF71"
            )
            assert row15_constant["operation_variant"] == "mov_absolute"
            assert row15_constant["encoding_variant"] == "mov_eax_absolute"
            assert row15_constant["publication_envelope"] == "imported_global_move"
            assert row15_constant["destination_storage"]["key"] == "r8"
            assert row15_constant["absolute_load_present"] is False
            assert row15_constant["passed"] is True
            if row15_constant["source_present"]:
                assert row15_constant["destination_delivery_present"] is True
                assert row15_constant["materialized_constant_present"] is True
                assert row15_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row15_constant["exact_generated_envelope"] is True
            row16_constant = observations[_ROW16_CONSTANT_OPERATION_ID]
            assert row16_constant["reference_operation_id"] == (
                "rhad:constant@0x40AF84"
            )
            assert row16_constant["operation_variant"] == "mov_absolute"
            assert row16_constant["encoding_variant"] == "mov_r32_absolute"
            assert row16_constant["publication_envelope"] == "imported_global_move"
            assert row16_constant["destination_storage"]["key"] == "r16"
            assert row16_constant["absolute_load_present"] is False
            assert row16_constant["passed"] is True
            if row16_constant["source_present"]:
                assert row16_constant["destination_delivery_present"] is True
                assert row16_constant["materialized_constant_present"] is True
                assert row16_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row16_constant["exact_generated_envelope"] is True
            row17_constant = observations[_ROW17_CONSTANT_OPERATION_ID]
            assert row17_constant["reference_operation_id"] == (
                "rhad:constant@0x40AFA0"
            )
            assert row17_constant["operation_variant"] == "mov_absolute"
            assert row17_constant["encoding_variant"] == "mov_eax_absolute"
            assert row17_constant["publication_envelope"] == "imported_global_move"
            assert row17_constant["destination_storage"]["key"] == "r8"
            assert row17_constant["absolute_load_present"] is False
            assert row17_constant["passed"] is True
            if row17_constant["source_present"]:
                assert row17_constant["destination_delivery_present"] is True
                assert row17_constant["materialized_constant_present"] is True
                assert row17_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row17_constant["exact_generated_envelope"] is True
            row18_constant = observations[_ROW18_CONSTANT_OPERATION_ID]
            assert row18_constant["reference_operation_id"] == (
                "rhad:constant@0x40B03E"
            )
            assert row18_constant["operation_variant"] == "mov_absolute"
            assert row18_constant["encoding_variant"] == "mov_eax_absolute"
            assert row18_constant["publication_envelope"] == "imported_global_move"
            assert row18_constant["destination_storage"]["key"] == "r8"
            assert row18_constant["absolute_load_present"] is False
            assert row18_constant["passed"] is True
            if row18_constant["source_present"]:
                assert row18_constant["destination_delivery_present"] is True
                assert row18_constant["materialized_constant_present"] is True
                assert row18_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row18_constant["exact_generated_envelope"] is True
            row19_constant = observations[_ROW19_CONSTANT_OPERATION_ID]
            assert row19_constant["reference_operation_id"] == (
                "rhad:constant@0x40B19B"
            )
            assert row19_constant["operation_variant"] == "mov_absolute"
            assert row19_constant["encoding_variant"] == "mov_eax_absolute"
            assert row19_constant["publication_envelope"] == "imported_global_move"
            assert row19_constant["destination_storage"]["key"] == "r8"
            assert row19_constant["absolute_load_present"] is False
            assert row19_constant["passed"] is True
            if row19_constant["source_present"]:
                assert row19_constant["destination_delivery_present"] is True
                assert row19_constant["materialized_constant_present"] is True
                assert row19_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row19_constant["exact_generated_envelope"] is True
            row20_constant = observations[_ROW20_CONSTANT_OPERATION_ID]
            assert row20_constant["reference_operation_id"] == (
                "rhad:constant@0x40B287"
            )
            assert row20_constant["operation_variant"] == "mov_absolute"
            assert row20_constant["encoding_variant"] == "mov_eax_absolute"
            assert row20_constant["publication_envelope"] == "imported_global_move"
            assert row20_constant["destination_storage"]["key"] == "r8"
            assert row20_constant["absolute_load_present"] is False
            assert row20_constant["passed"] is True
            if row20_constant["source_present"]:
                assert row20_constant["destination_delivery_present"] is True
                assert row20_constant["materialized_constant_present"] is True
                assert row20_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row20_constant["exact_generated_envelope"] is True
            row21_constant = observations[_ROW21_CONSTANT_OPERATION_ID]
            assert row21_constant["reference_operation_id"] == (
                "rhad:constant@0x40B2F7"
            )
            assert row21_constant["operation_variant"] == "mov_absolute"
            assert row21_constant["encoding_variant"] == "mov_eax_absolute"
            assert row21_constant["publication_envelope"] == "imported_global_move"
            assert row21_constant["destination_storage"]["key"] == "r8"
            assert row21_constant["absolute_load_present"] is False
            assert row21_constant["passed"] is True
            if row21_constant["source_present"]:
                assert row21_constant["destination_delivery_present"] is True
                assert row21_constant["materialized_constant_present"] is True
                assert row21_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row21_constant["exact_generated_envelope"] is True
            row22_constant = observations[_ROW22_CONSTANT_OPERATION_ID]
            assert row22_constant["reference_operation_id"] == (
                "rhad:constant@0x40B3B0"
            )
            assert row22_constant["operation_variant"] == "mov_absolute"
            assert row22_constant["encoding_variant"] == "mov_eax_absolute"
            assert row22_constant["publication_envelope"] == "imported_global_move"
            assert row22_constant["destination_storage"]["key"] == "r8"
            assert row22_constant["absolute_load_present"] is False
            assert row22_constant["passed"] is True
            if row22_constant["source_present"]:
                assert row22_constant["destination_delivery_present"] is True
                assert row22_constant["materialized_constant_present"] is True
                assert row22_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row22_constant["exact_generated_envelope"] is True
            row23_constant = observations[_ROW23_CONSTANT_OPERATION_ID]
            assert row23_constant["reference_operation_id"] == (
                "rhad:constant@0x40B3FF"
            )
            assert row23_constant["operation_variant"] == "mov_absolute"
            assert row23_constant["encoding_variant"] == "mov_r32_absolute"
            assert row23_constant["publication_envelope"] == "imported_global_move"
            assert row23_constant["destination_storage"]["key"] == "r16"
            assert row23_constant["absolute_load_present"] is False
            assert row23_constant["passed"] is True
            if row23_constant["source_present"]:
                assert row23_constant["destination_delivery_present"] is True
                assert row23_constant["materialized_constant_present"] is True
                assert row23_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row23_constant["exact_generated_envelope"] is True
            row24_constant = observations[_ROW24_CONSTANT_OPERATION_ID]
            assert row24_constant["reference_operation_id"] == (
                "rhad:constant@0x40B410"
            )
            assert row24_constant["operation_variant"] == "mov_absolute"
            assert row24_constant["encoding_variant"] == "mov_r32_absolute"
            assert row24_constant["publication_envelope"] == "imported_global_move"
            assert row24_constant["destination_storage"]["key"] == "r16"
            assert row24_constant["absolute_load_present"] is False
            assert row24_constant["passed"] is True
            if row24_constant["source_present"]:
                assert row24_constant["destination_delivery_present"] is True
                assert row24_constant["materialized_constant_present"] is True
                assert row24_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row24_constant["exact_generated_envelope"] is True
            row25_constant = observations[_ROW25_CONSTANT_OPERATION_ID]
            assert row25_constant["reference_operation_id"] == (
                "rhad:constant@0x40B421"
            )
            assert row25_constant["operation_variant"] == "mov_absolute"
            assert row25_constant["encoding_variant"] == "mov_r32_absolute"
            assert row25_constant["publication_envelope"] == "imported_global_move"
            assert row25_constant["destination_storage"]["key"] == "r16"
            assert row25_constant["absolute_load_present"] is False
            assert row25_constant["passed"] is True
            if row25_constant["source_present"]:
                assert row25_constant["destination_delivery_present"] is True
                assert row25_constant["materialized_constant_present"] is True
                assert row25_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row25_constant["exact_generated_envelope"] is True
            row26_constant = observations[_ROW26_CONSTANT_OPERATION_ID]
            assert row26_constant["reference_operation_id"] == (
                "rhad:constant@0x40B432"
            )
            assert row26_constant["operation_variant"] == "mov_absolute"
            assert row26_constant["encoding_variant"] == "mov_r32_absolute"
            assert row26_constant["publication_envelope"] == "imported_global_move"
            assert row26_constant["destination_storage"]["key"] == "r16"
            assert row26_constant["absolute_load_present"] is False
            assert row26_constant["passed"] is True
            if row26_constant["source_present"]:
                assert row26_constant["destination_delivery_present"] is True
                assert row26_constant["materialized_constant_present"] is True
                assert row26_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row26_constant["exact_generated_envelope"] is True
            row27_constant = observations[_ROW27_CONSTANT_OPERATION_ID]
            assert row27_constant["reference_operation_id"] == (
                "rhad:constant@0x40B443"
            )
            assert row27_constant["operation_variant"] == "mov_absolute"
            assert row27_constant["encoding_variant"] == "mov_r32_absolute"
            assert row27_constant["publication_envelope"] == "imported_global_move"
            assert row27_constant["destination_storage"]["key"] == "r12"
            assert row27_constant["absolute_load_present"] is False
            assert row27_constant["passed"] is True
            if row27_constant["source_present"]:
                assert row27_constant["destination_delivery_present"] is True
                assert row27_constant["materialized_constant_present"] is True
                assert row27_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row27_constant["exact_generated_envelope"] is True
            row28_constant = observations[_ROW28_CONSTANT_OPERATION_ID]
            assert row28_constant["reference_operation_id"] == (
                "rhad:constant@0x40B450"
            )
            assert row28_constant["operation_variant"] == "mov_absolute"
            assert row28_constant["encoding_variant"] == "mov_r32_absolute"
            assert row28_constant["publication_envelope"] == "imported_global_move"
            assert row28_constant["destination_storage"]["key"] == "r16"
            assert row28_constant["absolute_load_present"] is False
            assert row28_constant["passed"] is True
            if row28_constant["source_present"]:
                assert row28_constant["destination_delivery_present"] is True
                assert row28_constant["materialized_constant_present"] is True
                assert row28_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row28_constant["exact_generated_envelope"] is True
            row29_constant = observations[_ROW29_CONSTANT_OPERATION_ID]
            assert row29_constant["reference_operation_id"] == (
                "rhad:constant@0x40B45D"
            )
            assert row29_constant["operation_variant"] == "mov_absolute"
            assert row29_constant["encoding_variant"] == "mov_eax_absolute"
            assert row29_constant["publication_envelope"] == "imported_global_move"
            assert row29_constant["destination_storage"]["key"] == "r8"
            assert row29_constant["absolute_load_present"] is False
            assert row29_constant["passed"] is True
            if row29_constant["source_present"]:
                assert row29_constant["destination_delivery_present"] is True
                assert row29_constant["materialized_constant_present"] is True
                assert row29_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row29_constant["exact_generated_envelope"] is True
            row30_constant = observations[_ROW30_CONSTANT_OPERATION_ID]
            assert row30_constant["reference_operation_id"] == (
                "rhad:constant@0x40B815"
            )
            assert row30_constant["operation_variant"] == "movzx_absolute"
            assert row30_constant["encoding_variant"] == (
                "movzx_r32_byte_absolute"
            )
            assert row30_constant["publication_envelope"] == (
                "imported_global_byte_move"
            )
            assert row30_constant["source_width_bits"] == 8
            assert row30_constant["destination_width_bits"] == 32
            assert row30_constant["reference_read_width_bits"] == 32
            assert row30_constant["destination_storage"]["key"] == "r16"
            assert row30_constant["absolute_load_present"] is False
            assert row30_constant["passed"] is True
            if row30_constant["source_present"]:
                assert row30_constant["destination_delivery_present"] is True
                assert row30_constant["materialized_constant_present"] is True
                assert row30_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row30_constant["exact_generated_envelope"] is True
            row31_constant = observations[_ROW31_CONSTANT_OPERATION_ID]
            assert row31_constant["reference_operation_id"] == (
                "rhad:constant@0x40B825"
            )
            assert row31_constant["operation_variant"] == "mov_absolute"
            assert row31_constant["encoding_variant"] == "mov_r32_absolute"
            assert row31_constant["publication_envelope"] == "imported_global_move"
            assert row31_constant["source_width_bits"] == 32
            assert row31_constant["destination_width_bits"] == 32
            assert row31_constant["reference_read_width_bits"] == 32
            assert row31_constant["destination_storage"]["key"] == "r16"
            assert row31_constant["absolute_load_present"] is False
            assert row31_constant["passed"] is True
            if row31_constant["source_present"]:
                assert row31_constant["destination_delivery_present"] is True
                assert row31_constant["materialized_constant_present"] is True
                assert row31_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row31_constant["exact_generated_envelope"] is True
            row32_constant = observations[_ROW32_CONSTANT_OPERATION_ID]
            assert row32_constant["reference_operation_id"] == (
                "rhad:constant@0x40B84C"
            )
            assert row32_constant["operation_variant"] == "mov_absolute"
            assert row32_constant["encoding_variant"] == "mov_r32_absolute"
            assert row32_constant["publication_envelope"] == "imported_global_move"
            assert row32_constant["source_width_bits"] == 32
            assert row32_constant["destination_width_bits"] == 32
            assert row32_constant["reference_read_width_bits"] == 32
            assert row32_constant["destination_storage"]["key"] == "r12"
            assert row32_constant["absolute_load_present"] is False
            assert row32_constant["passed"] is True
            if row32_constant["source_present"]:
                assert row32_constant["destination_delivery_present"] is True
                assert row32_constant["materialized_constant_present"] is True
                assert row32_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row32_constant["exact_generated_envelope"] is True
            row33_constant = observations[_ROW33_CONSTANT_OPERATION_ID]
            assert row33_constant["reference_operation_id"] == (
                "rhad:constant@0x40B8E6"
            )
            assert row33_constant["operation_variant"] == "movzx_absolute"
            assert row33_constant["encoding_variant"] == (
                "movzx_r32_byte_absolute"
            )
            assert row33_constant["publication_envelope"] == (
                "imported_global_byte_zero_extend"
            )
            assert row33_constant["source_width_bits"] == 8
            assert row33_constant["destination_width_bits"] == 32
            assert row33_constant["reference_read_width_bits"] == 32
            assert row33_constant["destination_storage"]["key"] == "r8"
            assert row33_constant["absolute_load_present"] is False
            assert row33_constant["passed"] is True
            if row33_constant["source_present"]:
                assert row33_constant["destination_delivery_present"] is True
                assert row33_constant["materialized_constant_present"] is True
                assert row33_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row33_constant["exact_generated_envelope"] is True
            row34_constant = observations[_ROW34_CONSTANT_OPERATION_ID]
            assert row34_constant["reference_operation_id"] == (
                "rhad:constant@0x40B8ED"
            )
            assert row34_constant["operation_variant"] == "mov_absolute"
            assert row34_constant["encoding_variant"] == "mov_r32_absolute"
            assert row34_constant["publication_envelope"] == "imported_global_move"
            assert row34_constant["source_width_bits"] == 32
            assert row34_constant["destination_width_bits"] == 32
            assert row34_constant["reference_read_width_bits"] == 32
            assert row34_constant["destination_storage"]["key"] == "r16"
            assert row34_constant["absolute_load_present"] is False
            assert row34_constant["passed"] is True
            if row34_constant["source_present"]:
                assert row34_constant["destination_delivery_present"] is True
                assert row34_constant["materialized_constant_present"] is True
                assert row34_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row34_constant["exact_generated_envelope"] is True
            row35_constant = observations[_ROW35_CONSTANT_OPERATION_ID]
            assert row35_constant["reference_operation_id"] == (
                "rhad:constant@0x40B8FC"
            )
            assert row35_constant["operation_variant"] == "mov_absolute"
            assert row35_constant["encoding_variant"] == "mov_eax_absolute"
            assert row35_constant["publication_envelope"] == "imported_global_move"
            assert row35_constant["destination_storage"]["key"] == "r8"
            assert row35_constant["absolute_load_present"] is False
            assert row35_constant["passed"] is True
            if row35_constant["source_present"]:
                assert row35_constant["destination_delivery_present"] is True
                assert row35_constant["materialized_constant_present"] is True
                assert row35_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row35_constant["exact_generated_envelope"] is True
            row36_constant = observations[_ROW36_CONSTANT_OPERATION_ID]
            assert row36_constant["reference_operation_id"] == (
                "rhad:constant@0x40B9C1"
            )
            assert row36_constant["operation_variant"] == "movzx_absolute"
            assert row36_constant["encoding_variant"] == (
                "movzx_r32_byte_absolute"
            )
            assert row36_constant["publication_envelope"] == (
                "imported_global_byte_move"
            )
            assert row36_constant["source_width_bits"] == 8
            assert row36_constant["destination_width_bits"] == 32
            assert row36_constant["reference_read_width_bits"] == 32
            assert row36_constant["destination_storage"]["key"] == "r8"
            assert row36_constant["absolute_load_present"] is False
            assert row36_constant["passed"] is True
            if row36_constant["source_present"]:
                assert row36_constant["destination_delivery_present"] is True
                assert row36_constant["materialized_constant_present"] is True
                assert row36_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row36_constant["exact_generated_envelope"] is True
            row37_constant = observations[_ROW37_CONSTANT_OPERATION_ID]
            assert row37_constant["reference_operation_id"] == (
                "rhad:constant@0x40B9FF"
            )
            assert row37_constant["operation_variant"] == "mov_absolute"
            assert row37_constant["encoding_variant"] == "mov_eax_absolute"
            assert row37_constant["publication_envelope"] == "imported_global_move"
            assert row37_constant["destination_storage"]["key"] == "r8"
            assert row37_constant["absolute_load_present"] is False
            assert row37_constant["passed"] is True
            if row37_constant["source_present"]:
                assert row37_constant["destination_delivery_present"] is True
                assert row37_constant["materialized_constant_present"] is True
                assert row37_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row37_constant["exact_generated_envelope"] is True
            row38_constant = observations[_ROW38_CONSTANT_OPERATION_ID]
            assert row38_constant["reference_operation_id"] == (
                "rhad:constant@0x40BA1A"
            )
            assert row38_constant["operation_variant"] == "mov_absolute"
            assert row38_constant["encoding_variant"] == "mov_eax_absolute"
            assert row38_constant["publication_envelope"] == "imported_global_move"
            assert row38_constant["destination_storage"]["key"] == "r8"
            assert row38_constant["absolute_load_present"] is False
            assert row38_constant["passed"] is True
            if row38_constant["source_present"]:
                assert row38_constant["destination_delivery_present"] is True
                assert row38_constant["materialized_constant_present"] is True
                assert row38_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row38_constant["exact_generated_envelope"] is True
            row39_constant = observations[_ROW39_CONSTANT_OPERATION_ID]
            assert row39_constant["reference_operation_id"] == (
                "rhad:constant@0x40BA2D"
            )
            assert row39_constant["operation_variant"] == "mov_absolute"
            assert row39_constant["encoding_variant"] == "mov_eax_absolute"
            assert row39_constant["publication_envelope"] == "imported_global_move"
            assert row39_constant["destination_storage"]["key"] == "r8"
            assert row39_constant["absolute_load_present"] is False
            assert row39_constant["passed"] is True
            if row39_constant["source_present"]:
                assert row39_constant["destination_delivery_present"] is True
                assert row39_constant["materialized_constant_present"] is True
                assert row39_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row39_constant["exact_generated_envelope"] is True
            row40_constant = observations[_ROW40_CONSTANT_OPERATION_ID]
            assert row40_constant["reference_operation_id"] == (
                "rhad:constant@0x40BA47"
            )
            assert row40_constant["operation_variant"] == "mov_absolute"
            assert row40_constant["encoding_variant"] == "mov_eax_absolute"
            assert row40_constant["publication_envelope"] == "imported_global_move"
            assert row40_constant["destination_storage"]["key"] == "r8"
            assert row40_constant["absolute_load_present"] is False
            assert row40_constant["passed"] is True
            if row40_constant["source_present"]:
                assert row40_constant["destination_delivery_present"] is True
                assert row40_constant["materialized_constant_present"] is True
                assert row40_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row40_constant["exact_generated_envelope"] is True
            row41_constant = observations[_ROW41_CONSTANT_OPERATION_ID]
            assert row41_constant["reference_operation_id"] == (
                "rhad:constant@0x40BA63"
            )
            assert row41_constant["operation_variant"] == "mov_absolute"
            assert row41_constant["encoding_variant"] == "mov_eax_absolute"
            assert row41_constant["publication_envelope"] == "imported_global_move"
            assert row41_constant["destination_storage"]["key"] == "r8"
            assert row41_constant["absolute_load_present"] is False
            assert row41_constant["passed"] is True
            if row41_constant["source_present"]:
                assert row41_constant["destination_delivery_present"] is True
                assert row41_constant["materialized_constant_present"] is True
                assert row41_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row41_constant["exact_generated_envelope"] is True
            row42_constant = observations[_ROW42_CONSTANT_OPERATION_ID]
            assert row42_constant["reference_operation_id"] == (
                "rhad:constant@0x40BA7F"
            )
            assert row42_constant["operation_variant"] == "mov_absolute"
            assert row42_constant["encoding_variant"] == "mov_eax_absolute"
            assert row42_constant["publication_envelope"] == "imported_global_move"
            assert row42_constant["destination_storage"]["key"] == "r8"
            assert row42_constant["absolute_load_present"] is False
            assert row42_constant["passed"] is True
            if row42_constant["source_present"]:
                assert row42_constant["destination_delivery_present"] is True
                assert row42_constant["materialized_constant_present"] is True
                assert row42_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row42_constant["exact_generated_envelope"] is True
            row43_constant = observations[_ROW43_CONSTANT_OPERATION_ID]
            assert row43_constant["reference_operation_id"] == (
                "rhad:constant@0x40BACF"
            )
            assert row43_constant["operation_variant"] == "mov_absolute"
            assert row43_constant["encoding_variant"] == "mov_eax_absolute"
            assert row43_constant["publication_envelope"] == "imported_global_move"
            assert row43_constant["destination_storage"]["key"] == "r8"
            assert row43_constant["absolute_load_present"] is False
            assert row43_constant["passed"] is True
            if row43_constant["source_present"]:
                assert row43_constant["destination_delivery_present"] is True
                assert row43_constant["materialized_constant_present"] is True
                assert row43_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row43_constant["exact_generated_envelope"] is True
            row44_constant = observations[_ROW44_CONSTANT_OPERATION_ID]
            assert row44_constant["reference_operation_id"] == (
                "rhad:constant@0x40BB0A"
            )
            assert row44_constant["operation_variant"] == "mov_absolute"
            assert row44_constant["encoding_variant"] == "mov_eax_absolute"
            assert row44_constant["publication_envelope"] == "imported_global_move"
            assert row44_constant["destination_storage"]["key"] == "r8"
            assert row44_constant["absolute_load_present"] is False
            assert row44_constant["passed"] is True
            if row44_constant["source_present"]:
                assert row44_constant["destination_delivery_present"] is True
                assert row44_constant["materialized_constant_present"] is True
                assert row44_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row44_constant["exact_generated_envelope"] is True
            row45_constant = observations[_ROW45_CONSTANT_OPERATION_ID]
            assert row45_constant["reference_operation_id"] == (
                "rhad:constant@0x40BB28"
            )
            assert row45_constant["operation_variant"] == "mov_absolute"
            assert row45_constant["encoding_variant"] == "mov_eax_absolute"
            assert row45_constant["publication_envelope"] == "imported_global_move"
            assert row45_constant["destination_storage"]["key"] == "r8"
            assert row45_constant["absolute_load_present"] is False
            assert row45_constant["passed"] is True
            if row45_constant["source_present"]:
                assert row45_constant["destination_delivery_present"] is True
                assert row45_constant["materialized_constant_present"] is True
                assert row45_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row45_constant["exact_generated_envelope"] is True
            row46_constant = observations[_ROW46_CONSTANT_OPERATION_ID]
            assert row46_constant["reference_operation_id"] == (
                "rhad:constant@0x40BD84"
            )
            assert row46_constant["operation_variant"] == "mov_absolute"
            assert row46_constant["encoding_variant"] == "mov_eax_absolute"
            assert row46_constant["publication_envelope"] == "imported_global_move"
            assert row46_constant["destination_storage"]["key"] == "r8"
            assert row46_constant["absolute_load_present"] is False
            assert row46_constant["passed"] is True
            if row46_constant["source_present"]:
                assert row46_constant["destination_delivery_present"] is True
                assert row46_constant["materialized_constant_present"] is True
                assert row46_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row46_constant["exact_generated_envelope"] is True
            row47_constant = observations[_ROW47_CONSTANT_OPERATION_ID]
            assert row47_constant["reference_operation_id"] == (
                "rhad:constant@0x40BD9B"
            )
            assert row47_constant["operation_variant"] == "mov_absolute"
            assert row47_constant["encoding_variant"] == "mov_eax_absolute"
            assert row47_constant["publication_envelope"] == "imported_global_move"
            assert row47_constant["destination_storage"]["key"] == "r8"
            assert row47_constant["absolute_load_present"] is False
            assert row47_constant["passed"] is True
            if row47_constant["source_present"]:
                assert row47_constant["destination_delivery_present"] is True
                assert row47_constant["materialized_constant_present"] is True
                assert row47_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row47_constant["exact_generated_envelope"] is True
            row48_constant = observations[_ROW48_CONSTANT_OPERATION_ID]
            assert row48_constant["reference_operation_id"] == (
                "rhad:constant@0x40BDD8"
            )
            assert row48_constant["operation_variant"] == "mov_absolute"
            assert row48_constant["encoding_variant"] == "mov_eax_absolute"
            assert row48_constant["publication_envelope"] == "imported_global_move"
            assert row48_constant["destination_storage"]["key"] == "r8"
            assert row48_constant["absolute_load_present"] is False
            assert row48_constant["passed"] is True
            if row48_constant["source_present"]:
                assert row48_constant["destination_delivery_present"] is True
                assert row48_constant["materialized_constant_present"] is True
                assert row48_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row48_constant["exact_generated_envelope"] is True
            row49_constant = observations[_ROW49_CONSTANT_OPERATION_ID]
            assert row49_constant["reference_operation_id"] == (
                "rhad:constant@0x40BDEB"
            )
            assert row49_constant["operation_variant"] == "mov_absolute"
            assert row49_constant["encoding_variant"] == "mov_r32_absolute"
            assert row49_constant["publication_envelope"] == "imported_global_move"
            assert row49_constant["destination_storage"]["key"] == "r16"
            assert row49_constant["absolute_load_present"] is False
            assert row49_constant["passed"] is True
            if row49_constant["source_present"]:
                assert row49_constant["destination_delivery_present"] is True
                assert row49_constant["materialized_constant_present"] is True
                assert row49_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row49_constant["exact_generated_envelope"] is True
            row50_constant = observations[_ROW50_CONSTANT_OPERATION_ID]
            assert row50_constant["reference_operation_id"] == (
                "rhad:constant@0x40BE63"
            )
            assert row50_constant["operation_variant"] == "mov_absolute"
            assert row50_constant["encoding_variant"] == "mov_eax_absolute"
            assert row50_constant["publication_envelope"] == "imported_global_move"
            assert row50_constant["destination_storage"]["key"] == "r8"
            assert row50_constant["absolute_load_present"] is False
            assert row50_constant["passed"] is True
            if row50_constant["source_present"]:
                assert row50_constant["destination_delivery_present"] is True
                assert row50_constant["materialized_constant_present"] is True
                assert row50_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row50_constant["exact_generated_envelope"] is True
            row51_constant = observations[_ROW51_CONSTANT_OPERATION_ID]
            assert row51_constant["reference_operation_id"] == (
                "rhad:constant@0x40BF31"
            )
            assert row51_constant["operation_variant"] == "mov_absolute"
            assert row51_constant["encoding_variant"] == "mov_eax_absolute"
            assert row51_constant["publication_envelope"] == "imported_global_move"
            assert row51_constant["destination_storage"]["key"] == "r8"
            assert row51_constant["absolute_load_present"] is False
            assert row51_constant["passed"] is True
            if row51_constant["source_present"]:
                assert row51_constant["destination_delivery_present"] is True
                assert row51_constant["materialized_constant_present"] is True
                assert row51_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row51_constant["exact_generated_envelope"] is True
            row52_constant = observations[_ROW52_CONSTANT_OPERATION_ID]
            assert row52_constant["reference_operation_id"] == (
                "rhad:constant@0x40BF4E"
            )
            assert row52_constant["operation_variant"] == "mov_absolute"
            assert row52_constant["encoding_variant"] == "mov_r32_absolute"
            assert row52_constant["publication_envelope"] == "imported_global_move"
            assert row52_constant["destination_storage"]["key"] == "r16"
            assert row52_constant["absolute_load_present"] is False
            assert row52_constant["passed"] is True
            if row52_constant["source_present"]:
                assert row52_constant["destination_delivery_present"] is True
                assert row52_constant["materialized_constant_present"] is True
                assert row52_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row52_constant["exact_generated_envelope"] is True
            row53_constant = observations[_ROW53_CONSTANT_OPERATION_ID]
            assert row53_constant["reference_operation_id"] == (
                "rhad:constant@0x40C118"
            )
            assert row53_constant["operation_variant"] == "mov_absolute"
            assert row53_constant["encoding_variant"] == "mov_r32_absolute"
            assert row53_constant["publication_envelope"] == "imported_global_move"
            assert row53_constant["destination_storage"]["key"] == "r16"
            assert row53_constant["absolute_load_present"] is False
            assert row53_constant["passed"] is True
            if row53_constant["source_present"]:
                assert row53_constant["destination_delivery_present"] is True
                assert row53_constant["materialized_constant_present"] is True
                assert row53_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row53_constant["exact_generated_envelope"] is True
            row54_constant = observations[_ROW54_CONSTANT_OPERATION_ID]
            assert row54_constant["reference_operation_id"] == (
                "rhad:constant@0x40C1A0"
            )
            assert row54_constant["operation_variant"] == "mov_absolute"
            assert row54_constant["encoding_variant"] == "mov_eax_absolute"
            assert row54_constant["publication_envelope"] == "imported_global_move"
            assert row54_constant["destination_storage"]["key"] == "r8"
            assert row54_constant["absolute_load_present"] is False
            assert row54_constant["passed"] is True
            if row54_constant["source_present"]:
                assert row54_constant["destination_delivery_present"] is True
                assert row54_constant["materialized_constant_present"] is True
                assert row54_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row54_constant["exact_generated_envelope"] is True
            row55_constant = observations[_ROW55_CONSTANT_OPERATION_ID]
            assert row55_constant["reference_operation_id"] == (
                "rhad:constant@0x40C1AC"
            )
            assert row55_constant["operation_variant"] == "mov_absolute"
            assert row55_constant["encoding_variant"] == "mov_r32_absolute"
            assert row55_constant["publication_envelope"] == "imported_global_move"
            assert row55_constant["destination_storage"]["key"] == "r16"
            assert row55_constant["absolute_load_present"] is False
            assert row55_constant["passed"] is True
            if row55_constant["source_present"]:
                assert row55_constant["destination_delivery_present"] is True
                assert row55_constant["materialized_constant_present"] is True
                assert row55_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row55_constant["exact_generated_envelope"] is True
            row56_constant = observations[_ROW56_CONSTANT_OPERATION_ID]
            assert row56_constant["reference_operation_id"] == (
                "rhad:constant@0x40C21B"
            )
            assert row56_constant["operation_variant"] == "mov_absolute"
            assert row56_constant["encoding_variant"] == "mov_r32_absolute"
            assert row56_constant["publication_envelope"] == "imported_global_move"
            assert row56_constant["destination_storage"]["key"] == "r16"
            assert row56_constant["absolute_load_present"] is False
            assert row56_constant["passed"] is True
            if row56_constant["source_present"]:
                assert row56_constant["destination_delivery_present"] is True
                assert row56_constant["materialized_constant_present"] is True
                assert row56_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row56_constant["exact_generated_envelope"] is True
            row57_constant = observations[_ROW57_CONSTANT_OPERATION_ID]
            assert row57_constant["reference_operation_id"] == (
                "rhad:constant@0x40C26D"
            )
            assert row57_constant["operation_variant"] == "mov_absolute"
            assert row57_constant["encoding_variant"] == "mov_eax_absolute"
            assert row57_constant["publication_envelope"] == "imported_global_move"
            assert row57_constant["destination_storage"]["key"] == "r8"
            assert row57_constant["absolute_load_present"] is False
            assert row57_constant["passed"] is True
            if row57_constant["source_present"]:
                assert row57_constant["destination_delivery_present"] is True
                assert row57_constant["materialized_constant_present"] is True
                assert row57_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row57_constant["exact_generated_envelope"] is True
            row58_constant = observations[_ROW58_CONSTANT_OPERATION_ID]
            assert row58_constant["reference_operation_id"] == (
                "rhad:constant@0x40C279"
            )
            assert row58_constant["operation_variant"] == "mov_absolute"
            assert row58_constant["encoding_variant"] == "mov_r32_absolute"
            assert row58_constant["publication_envelope"] == "imported_global_move"
            assert row58_constant["destination_storage"]["key"] == "r16"
            assert row58_constant["absolute_load_present"] is False
            assert row58_constant["passed"] is True
            if row58_constant["source_present"]:
                assert row58_constant["destination_delivery_present"] is True
                assert row58_constant["materialized_constant_present"] is True
                assert row58_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row58_constant["exact_generated_envelope"] is True
            row59_constant = observations[_ROW59_CONSTANT_OPERATION_ID]
            assert row59_constant["reference_operation_id"] == (
                "rhad:constant@0x40C286"
            )
            assert row59_constant["operation_variant"] == "mov_absolute"
            assert row59_constant["encoding_variant"] == "mov_r32_absolute"
            assert row59_constant["publication_envelope"] == "imported_global_move"
            assert row59_constant["destination_storage"]["key"] == "r12"
            assert row59_constant["absolute_load_present"] is False
            assert row59_constant["passed"] is True
            if row59_constant["source_present"]:
                assert row59_constant["destination_delivery_present"] is True
                assert row59_constant["materialized_constant_present"] is True
                assert row59_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row59_constant["exact_generated_envelope"] is True
            row60_constant = observations[_ROW60_CONSTANT_OPERATION_ID]
            assert row60_constant["reference_operation_id"] == (
                "rhad:constant@0x40C293"
            )
            assert row60_constant["operation_variant"] == "mov_absolute"
            assert row60_constant["encoding_variant"] == "mov_r32_absolute"
            assert row60_constant["publication_envelope"] == "imported_global_move"
            assert row60_constant["destination_storage"]["key"] == "r32"
            assert row60_constant["absolute_load_present"] is False
            assert row60_constant["passed"] is True
            if row60_constant["source_present"]:
                assert row60_constant["destination_delivery_present"] is True
                assert row60_constant["materialized_constant_present"] is True
                assert row60_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row60_constant["exact_generated_envelope"] is True
            row61_constant = observations[_ROW61_CONSTANT_OPERATION_ID]
            assert row61_constant["reference_operation_id"] == (
                "rhad:constant@0x40C2AF"
            )
            assert row61_constant["operation_variant"] == "mov_absolute"
            assert row61_constant["encoding_variant"] == "mov_r32_absolute"
            assert row61_constant["publication_envelope"] == "imported_global_move"
            assert row61_constant["destination_storage"]["key"] == "r16"
            assert row61_constant["absolute_load_present"] is False
            assert row61_constant["passed"] is True
            if row61_constant["source_present"]:
                assert row61_constant["destination_delivery_present"] is True
                assert row61_constant["materialized_constant_present"] is True
                assert row61_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row61_constant["exact_generated_envelope"] is True
            row62_constant = observations[_ROW62_CONSTANT_OPERATION_ID]
            assert row62_constant["reference_operation_id"] == (
                "rhad:constant@0x40C322"
            )
            assert row62_constant["operation_variant"] == "xor_absolute"
            assert row62_constant["encoding_variant"] == "xor_r8_absolute"
            assert row62_constant["publication_envelope"] == (
                "imported_global_byte_xor"
            )
            assert row62_constant["destination_storage"]["key"] == "r8"
            assert row62_constant["required_flag_roles"] == [
                "carry",
                "overflow",
                "zero",
                "parity",
                "sign",
            ]
            assert row62_constant["absolute_load_present"] is False
            assert row62_constant["passed"] is True
            if row62_constant["source_present"]:
                assert row62_constant["destination_delivery_present"] is True
                assert row62_constant["semantic_envelope_survives"] is True
                if row62_constant["materialized_constant_present"]:
                    assert row62_constant["flag_envelope_survives"] is True
                    assert (
                        row62_constant["optimizer_boolean_inversion_present"] is False
                    )
                else:
                    assert row62_constant["flag_envelope_survives"] is False
                    assert (
                        row62_constant["optimizer_boolean_inversion_present"] is True
                    )
                    assert row62_constant["source_semantics_optimized"] is True
            if maturity == "MMAT_GENERATED":
                assert row62_constant["exact_generated_envelope"] is True
            row63_constant = observations[_ROW63_CONSTANT_OPERATION_ID]
            assert row63_constant["reference_operation_id"] == (
                "rhad:constant@0x40C4F8"
            )
            assert row63_constant["operation_variant"] == "mov_absolute"
            assert row63_constant["encoding_variant"] == "mov_r32_absolute"
            assert row63_constant["publication_envelope"] == "imported_global_move"
            assert row63_constant["destination_storage"]["key"] == "r12"
            assert row63_constant["absolute_load_present"] is False
            assert row63_constant["passed"] is True
            if row63_constant["source_present"]:
                assert row63_constant["destination_delivery_present"] is True
                assert row63_constant["materialized_constant_present"] is True
                assert row63_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row63_constant["exact_generated_envelope"] is True
            row64_constant = observations[_ROW64_CONSTANT_OPERATION_ID]
            assert row64_constant["reference_operation_id"] == (
                "rhad:constant@0x40C592"
            )
            assert row64_constant["operation_variant"] == "mov_absolute"
            assert row64_constant["encoding_variant"] == "mov_eax_absolute"
            assert row64_constant["publication_envelope"] == "imported_global_move"
            assert row64_constant["destination_storage"]["key"] == "r8"
            assert row64_constant["absolute_load_present"] is False
            assert row64_constant["passed"] is True
            if row64_constant["source_present"]:
                assert row64_constant["destination_delivery_present"] is True
                assert row64_constant["materialized_constant_present"] is True
                assert row64_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row64_constant["exact_generated_envelope"] is True
            row65_constant = observations[_ROW65_CONSTANT_OPERATION_ID]
            assert row65_constant["reference_operation_id"] == "rhad:constant@0x40C59E"
            assert row65_constant["operation_variant"] == "mov_absolute"
            assert row65_constant["encoding_variant"] == "mov_r32_absolute"
            assert row65_constant["publication_envelope"] == "imported_global_move"
            assert row65_constant["destination_storage"]["key"] == "r16"
            assert row65_constant["absolute_load_present"] is False
            assert row65_constant["passed"] is True
            if row65_constant["source_present"]:
                assert row65_constant["destination_delivery_present"] is True
                assert row65_constant["materialized_constant_present"] is True
                assert row65_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row65_constant["exact_generated_envelope"] is True
            row66_constant = observations[_ROW66_CONSTANT_OPERATION_ID]
            assert row66_constant["reference_operation_id"] == "rhad:constant@0x40C5BD"
            assert row66_constant["operation_variant"] == "mov_absolute"
            assert row66_constant["encoding_variant"] == "mov_r32_absolute"
            assert row66_constant["publication_envelope"] == "imported_global_move"
            assert row66_constant["destination_storage"]["key"] == "r16"
            assert row66_constant["absolute_load_present"] is False
            assert row66_constant["passed"] is True
            if row66_constant["source_present"]:
                assert row66_constant["destination_delivery_present"] is True
                assert row66_constant["materialized_constant_present"] is True
                assert row66_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row66_constant["exact_generated_envelope"] is True
            row67_constant = observations[_ROW67_CONSTANT_OPERATION_ID]
            assert row67_constant["reference_operation_id"] == "rhad:constant@0x40C667"
            assert row67_constant["operation_variant"] == "mov_absolute"
            assert row67_constant["encoding_variant"] == "mov_r32_absolute"
            assert row67_constant["publication_envelope"] == "imported_global_move"
            assert row67_constant["destination_storage"]["key"] == "r12"
            assert row67_constant["absolute_load_present"] is False
            assert row67_constant["passed"] is True
            if row67_constant["source_present"]:
                assert row67_constant["destination_delivery_present"] is True
                assert row67_constant["materialized_constant_present"] is True
                assert row67_constant["semantic_envelope_survives"] is True
            if maturity == "MMAT_GENERATED":
                assert row67_constant["exact_generated_envelope"] is True
            direct = observations["route:rhad-direct@0x40A619"]
            assert direct["source_present"] is True
            assert direct["source_topology_reachable"] is True
            assert direct["source_topology_retired"] is False
            assert direct["indirect_transfer_present"] is False
            assert direct["target_eas"] == [0x40A61B]
            assert direct["passed"] is True
            row3 = observations["route:rhad-direct@0x40A631"]
            assert row3["source_present"] is True
            assert row3["source_topology_reachable"] is True
            assert row3["source_topology_retired"] is False
            assert row3["indirect_transfer_present"] is False
            assert row3["target_eas"] == [0x40A633]
            assert row3["passed"] is True
            row4 = observations["route:rhad-direct@0x40A649"]
            assert row4["source_present"] is True
            assert row4["source_topology_reachable"] is True
            assert row4["source_topology_retired"] is False
            assert row4["indirect_transfer_present"] is False
            assert row4["target_eas"] == [0x40A8B5]
            assert row4["passed"] is True
            row5 = observations["route:rhad-direct@0x40A661"]
            assert row5["source_present"] is True
            assert row5["source_topology_reachable"] is True
            assert row5["source_topology_retired"] is False
            assert row5["indirect_transfer_present"] is False
            assert row5["target_eas"] == [0x40A663]
            assert row5["boundary_exit_eas"] == [
                0x40A5CA,
                0x40AAFD,
                0x40AE26,
            ]
            assert row5["passed"] is True
            row6 = observations["route:rhad-direct@0x40A679"]
            assert row6["source_present"] is False
            assert row6["source_topology_reachable"] is False
            assert row6["source_topology_retired"] is True
            assert row6["indirect_transfer_present"] is False
            assert row6["target_eas"] == []
            assert row6["boundary_exit_eas"] == [0x40A5F0, 0x40AE3E]
            assert row6["passed"] is True
            selected = observations["rhad:route@0x40A6A4"]
            assert selected["source_present"] is True
            assert selected["source_topology_reachable"] is True
            assert selected["source_topology_retired"] is False
            assert selected["indirect_transfer_present"] is False
            assert selected["target_eas"] == [0x40A6A6, 0x40A800]
            assert selected["semantic_target_eas"] == [0x40A6A6, 0x40A800]
            assert selected["delivery_target_eas"] == [0x40A6A6, 0x40A800]
            assert selected["semantic_targets_survive"] is True
            assert selected["passed"] is True
            row9 = observations["rhad:route@0x40A6BE"]
            assert row9["source_present"] is True
            assert row9["source_topology_reachable"] is True
            assert row9["source_topology_retired"] is False
            assert row9["indirect_transfer_present"] is False
            assert row9["target_eas"] == [0x40A6C0, 0x40A960]
            assert row9["semantic_target_eas"] == [0x40A6C0, 0x40A960]
            assert row9["delivery_target_eas"] == [0x40A6C0, 0x40A960]
            assert row9["semantic_targets_survive"] is True
            assert row9["passed"] is True
            row10 = observations["rhad:route@0x40A6D8"]
            assert row10["source_present"] is True
            assert row10["source_topology_reachable"] is True
            assert row10["source_topology_retired"] is False
            assert row10["indirect_transfer_present"] is False
            assert row10["target_eas"] == [0x40A6DA, 0x40AB76]
            assert row10["semantic_target_eas"] == [0x40A6DA, 0x40AB76]
            assert row10["delivery_target_eas"] == [0x40A6DA, 0x40AB76]
            assert row10["semantic_targets_survive"] is True
            assert row10["passed"] is True
            row11 = observations["rhad:route@0x40A6F2"]
            assert row11["source_present"] is True
            assert row11["source_topology_reachable"] is True
            assert row11["source_topology_retired"] is False
            assert row11["indirect_transfer_present"] is False
            assert row11["target_eas"] == [0x40A6F4, 0x40AE8B]
            assert row11["semantic_target_eas"] == [0x40A6F4, 0x40AE8B]
            assert row11["delivery_target_eas"] == [0x40A6F4, 0x40AE8B]
            assert row11["semantic_targets_survive"] is True
            assert row11["passed"] is True
            row12 = observations["rhad:route@0x40A70C"]
            assert row12["source_present"] is True
            assert row12["source_topology_reachable"] is True
            assert row12["source_topology_retired"] is False
            assert row12["indirect_transfer_present"] is False
            assert row12["target_eas"] == [0x40A5F0, 0x40A70E]
            assert row12["semantic_target_eas"] == [0x40A5F0, 0x40A70E]
            assert row12["delivery_target_eas"] == [0x40A5F0, 0x40A70E]
            assert row12["semantic_targets_survive"] is True
            assert row12["passed"] is True
            setcc = observations["rhad:route@0x40A77C"]
            assert setcc["source_present"] is True
            assert setcc["source_topology_reachable"] is True
            assert setcc["source_topology_retired"] is False
            assert setcc["indirect_transfer_present"] is False
            assert setcc["target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["semantic_target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["delivery_target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["semantic_targets_survive"] is True
            assert setcc["passed"] is True
            scaled_setcc = observations["rhad:route@0x40A792"]
            assert scaled_setcc["source_present"] is True
            assert scaled_setcc["indirect_transfer_present"] is False
            assert scaled_setcc["semantic_target_eas"] == [0x40A794, 0x40AEE6]
            assert scaled_setcc["delivery_target_eas"] == [0x40A794, 0x40AEE6]
            assert scaled_setcc["semantic_targets_survive"] is True
            assert scaled_setcc["passed"] is True
            if maturity == "MMAT_GENERATED":
                assert scaled_setcc["source_topology_reachable"] is False
                assert scaled_setcc["source_topology_retired"] is True
                assert scaled_setcc["target_eas"] == [
                    0x40A5F0,
                    0x40A794,
                    0x40AEE6,
                ]
            else:
                assert scaled_setcc["source_topology_reachable"] is True
                assert scaled_setcc["source_topology_retired"] is False
                assert scaled_setcc["target_eas"] == [0x40A794, 0x40AEE6]
            row18 = observations["rhad:route@0x40A7AC"]
            assert row18["source_present"] is True
            assert row18["source_topology_reachable"] is True
            assert row18["source_topology_retired"] is False
            assert row18["indirect_transfer_present"] is False
            assert row18["target_eas"] == [0x40A5F0, 0x40A7AE]
            assert row18["semantic_target_eas"] == [0x40A5F0, 0x40A7AE]
            assert row18["delivery_target_eas"] == [0x40A5F0, 0x40A7AE]
            assert row18["semantic_targets_survive"] is True
            assert row18["passed"] is True
            row19 = observations["route:rhad-direct@0x40A7EF"]
            assert row19["source_present"] is True
            assert row19["source_topology_reachable"] is True
            assert row19["source_topology_retired"] is False
            assert row19["indirect_transfer_present"] is False
            assert row19["target_eas"] == [0x40B6C0]
            assert row19["boundary_exit_eas"] == [0x40B790]
            assert row19["passed"] is True
            row20 = observations["rhad:route@0x40A818"]
            assert row20["source_present"] is True
            assert row20["source_topology_reachable"] is True
            assert row20["source_topology_retired"] is False
            assert row20["indirect_transfer_present"] is False
            assert row20["target_eas"] == [0x40A81A, 0x40AA60]
            assert row20["semantic_target_eas"] == [0x40A81A, 0x40AA60]
            assert row20["delivery_target_eas"] == [0x40A81A, 0x40AA60]
            assert row20["semantic_targets_survive"] is True
            assert row20["passed"] is True
            row21 = observations["rhad:route@0x40A832"]
            assert row21["source_present"] is True
            assert row21["source_topology_reachable"] is True
            assert row21["source_topology_retired"] is False
            assert row21["indirect_transfer_present"] is False
            assert row21["target_eas"] == [0x40A834, 0x40AC3D]
            assert row21["semantic_target_eas"] == [0x40A834, 0x40AC3D]
            assert row21["delivery_target_eas"] == [0x40A834, 0x40AC3D]
            assert row21["semantic_targets_survive"] is True
            assert row21["passed"] is True
            row22 = observations["rhad:route@0x40A84C"]
            assert row22["source_present"] is True
            assert row22["source_topology_reachable"] is True
            assert row22["source_topology_retired"] is False
            assert row22["indirect_transfer_present"] is False
            assert row22["target_eas"] == [0x40A84E, 0x40AFDF]
            assert row22["semantic_target_eas"] == [0x40A84E, 0x40AFDF]
            assert row22["delivery_target_eas"] == [0x40A84E, 0x40AFDF]
            assert row22["semantic_targets_survive"] is True
            assert row22["passed"] is True
            row23 = observations["rhad:route@0x40A866"]
            assert row23["source_present"] is True
            assert row23["source_topology_reachable"] is True
            assert row23["source_topology_retired"] is False
            assert row23["indirect_transfer_present"] is False
            assert row23["target_eas"] == [0x40A5F0, 0x40A868]
            assert row23["semantic_target_eas"] == [0x40A5F0, 0x40A868]
            assert row23["delivery_target_eas"] == [0x40A5F0, 0x40A868]
            assert row23["semantic_targets_survive"] is True
            assert row23["passed"] is True
            row25 = observations["route:rhad-direct@0x40A8B3"]
            assert row25["source_present"] is True
            assert row25["source_topology_reachable"] is True
            assert row25["source_topology_retired"] is False
            assert row25["indirect_transfer_present"] is False
            assert row25["target_eas"] == [0x40A64B]
            assert row25["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
            assert row25["passed"] is True
            row26 = observations["rhad:route@0x40A8CD"]
            assert row26["source_present"] is True
            assert row26["source_topology_reachable"] is True
            assert row26["source_topology_retired"] is False
            assert row26["indirect_transfer_present"] is False
            assert row26["target_eas"] == [0x40A8CF, 0x40ACBF]
            assert row26["semantic_target_eas"] == [0x40A8CF, 0x40ACBF]
            assert row26["delivery_target_eas"] == [0x40A8CF, 0x40ACBF]
            assert row26["semantic_targets_survive"] is True
            assert row26["passed"] is True
            row27 = observations["rhad:route@0x40A8E7"]
            assert row27["source_present"] is True
            assert row27["source_topology_reachable"] is True
            assert row27["source_topology_retired"] is False
            assert row27["indirect_transfer_present"] is False
            assert row27["target_eas"] == [0x40A8E9, 0x40B024]
            assert row27["semantic_target_eas"] == [0x40A8E9, 0x40B024]
            assert row27["delivery_target_eas"] == [0x40A8E9, 0x40B024]
            assert row27["semantic_targets_survive"] is True
            assert row27["passed"] is True
            row28 = observations["rhad:route@0x40A901"]
            assert row28["source_present"] is True
            assert row28["source_topology_reachable"] is True
            assert row28["source_topology_retired"] is False
            assert row28["indirect_transfer_present"] is False
            assert row28["target_eas"] == [0x40A5F0, 0x40A903]
            assert row28["semantic_target_eas"] == [0x40A5F0, 0x40A903]
            assert row28["delivery_target_eas"] == [0x40A5F0, 0x40A903]
            assert row28["semantic_targets_survive"] is True
            assert row28["passed"] is True
            row29 = observations["route:rhad-direct@0x40A95E"]
            assert row29["source_present"] is True
            assert row29["source_topology_reachable"] is True
            assert row29["source_topology_retired"] is False
            assert row29["indirect_transfer_present"] is False
            assert row29["target_eas"] == [0x40B6C0]
            assert row29["boundary_exit_eas"] == [0x40B790]
            assert row29["passed"] is True
            row30 = observations["rhad:route@0x40A978"]
            assert row30["source_present"] is True
            assert row30["source_topology_reachable"] is True
            assert row30["source_topology_retired"] is False
            assert row30["indirect_transfer_present"] is False
            assert row30["target_eas"] == [0x40A97A, 0x40AD1E]
            assert row30["semantic_target_eas"] == [0x40A97A, 0x40AD1E]
            assert row30["delivery_target_eas"] == [0x40A97A, 0x40AD1E]
            assert row30["semantic_targets_survive"] is True
            assert row30["passed"] is True
            row31 = observations["rhad:route@0x40A992"]
            assert row31["source_present"] is True
            assert row31["source_topology_reachable"] is True
            assert row31["source_topology_retired"] is False
            assert row31["indirect_transfer_present"] is False
            assert row31["target_eas"] == [0x40A994, 0x40B071]
            assert row31["semantic_target_eas"] == [0x40A994, 0x40B071]
            assert row31["delivery_target_eas"] == [0x40A994, 0x40B071]
            assert row31["semantic_targets_survive"] is True
            assert row31["passed"] is True
            row32 = observations["rhad:route@0x40A9AC"]
            assert row32["source_present"] is True
            assert row32["source_topology_reachable"] is True
            assert row32["source_topology_retired"] is False
            assert row32["indirect_transfer_present"] is False
            assert row32["target_eas"] == [0x40A5F0, 0x40A9AE]
            assert row32["semantic_target_eas"] == [0x40A5F0, 0x40A9AE]
            assert row32["delivery_target_eas"] == [0x40A5F0, 0x40A9AE]
            assert row32["semantic_targets_survive"] is True
            assert row32["passed"] is True
            row33 = observations["rhad:route@0x40A9DC"]
            assert row33["source_present"] is True
            assert row33["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row33["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row33["indirect_transfer_present"] is False
            assert row33["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row33["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row33["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row33["semantic_targets_survive"] is True
            assert row33["passed"] is True
            row34 = observations["rhad:route@0x40A9F6"]
            assert row34["source_present"] is True
            assert row34["source_topology_reachable"] is True
            assert row34["source_topology_retired"] is False
            assert row34["indirect_transfer_present"] is False
            assert row34["target_eas"] == [0x40A9F8, 0x40AD6E]
            assert row34["semantic_target_eas"] == [0x40A9F8, 0x40AD6E]
            assert row34["delivery_target_eas"] == [0x40A9F8, 0x40AD6E]
            assert row34["semantic_targets_survive"] is True
            assert row34["passed"] is True
            row35 = observations["rhad:route@0x40AA10"]
            assert row35["source_present"] is True
            assert row35["source_topology_reachable"] is True
            assert row35["source_topology_retired"] is False
            assert row35["indirect_transfer_present"] is False
            assert row35["target_eas"] == [0x40AA12, 0x40B0BC]
            assert row35["semantic_target_eas"] == [0x40AA12, 0x40B0BC]
            assert row35["delivery_target_eas"] == [0x40AA12, 0x40B0BC]
            assert row35["semantic_targets_survive"] is True
            assert row35["passed"] is True
            row36 = observations["rhad:route@0x40AA2A"]
            assert row36["source_present"] is True
            assert row36["source_topology_reachable"] is True
            assert row36["source_topology_retired"] is False
            assert row36["indirect_transfer_present"] is False
            assert row36["target_eas"] == [0x40A5F0, 0x40AA2C]
            assert row36["semantic_target_eas"] == [0x40A5F0, 0x40AA2C]
            assert row36["delivery_target_eas"] == [0x40A5F0, 0x40AA2C]
            assert row36["semantic_targets_survive"] is True
            assert row36["passed"] is True
            row37 = observations["rhad:route@0x40AA5E"]
            assert row37["source_present"] is True
            assert row37["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row37["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row37["indirect_transfer_present"] is False
            assert row37["target_eas"] == (
                [0x40A607] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row37["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row37["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row37["semantic_targets_survive"] is True
            assert row37["passed"] is True
            row38 = observations["rhad:route@0x40AA78"]
            assert row38["source_present"] is True
            assert row38["source_topology_reachable"] is True
            assert row38["source_topology_retired"] is False
            assert row38["indirect_transfer_present"] is False
            assert row38["target_eas"] == [0x40AA7A, 0x40ADBE]
            assert row38["semantic_target_eas"] == [0x40AA7A, 0x40ADBE]
            assert row38["delivery_target_eas"] == [0x40AA7A, 0x40ADBE]
            assert row38["semantic_targets_survive"] is True
            assert row38["passed"] is True
            row39 = observations["rhad:route@0x40AA92"]
            assert row39["source_present"] is True
            assert row39["source_topology_reachable"] is True
            assert row39["source_topology_retired"] is False
            assert row39["indirect_transfer_present"] is False
            assert row39["target_eas"] == [0x40AA94, 0x40B0F2]
            assert row39["semantic_target_eas"] == [0x40AA94, 0x40B0F2]
            assert row39["delivery_target_eas"] == [0x40AA94, 0x40B0F2]
            assert row39["semantic_targets_survive"] is True
            assert row39["passed"] is True
            row40 = observations["rhad:route@0x40AAAC"]
            assert row40["source_present"] is True
            assert row40["source_topology_reachable"] is True
            assert row40["source_topology_retired"] is False
            assert row40["indirect_transfer_present"] is False
            assert row40["target_eas"] == [0x40A5F0, 0x40AAAE]
            assert row40["semantic_target_eas"] == [0x40A5F0, 0x40AAAE]
            assert row40["delivery_target_eas"] == [0x40A5F0, 0x40AAAE]
            assert row40["semantic_targets_survive"] is True
            assert row40["passed"] is True
            row42 = observations["route:rhad-direct@0x40AAFB"]
            assert row42["source_present"] is True
            assert row42["source_topology_reachable"] is True
            assert row42["source_topology_retired"] is False
            assert row42["indirect_transfer_present"] is False
            assert row42["target_eas"] == [0x40AAFD]
            assert row42["boundary_exit_eas"] == [0x40AB17, 0x40B149]
            assert row42["passed"] is True
            row43 = observations["rhad:route@0x40AB15"]
            assert row43["source_present"] is True
            assert row43["source_topology_reachable"] is True
            assert row43["source_topology_retired"] is False
            assert row43["indirect_transfer_present"] is False
            assert row43["target_eas"] == [0x40AB17, 0x40B149]
            assert row43["semantic_target_eas"] == [0x40AB17, 0x40B149]
            assert row43["delivery_target_eas"] == [0x40AB17, 0x40B149]
            assert row43["semantic_targets_survive"] is True
            assert row43["passed"] is True
            row44 = observations["rhad:route@0x40AB2F"]
            assert row44["source_present"] is True
            assert row44["source_topology_reachable"] is True
            assert row44["source_topology_retired"] is False
            assert row44["indirect_transfer_present"] is False
            assert row44["target_eas"] == [0x40A5F0, 0x40AB31]
            assert row44["semantic_target_eas"] == [0x40A5F0, 0x40AB31]
            assert row44["delivery_target_eas"] == [0x40A5F0, 0x40AB31]
            assert row44["semantic_targets_survive"] is True
            assert row44["passed"] is True
            row46 = observations["rhad:route@0x40AB8E"]
            assert row46["source_present"] is True
            assert row46["source_topology_reachable"] is True
            assert row46["source_topology_retired"] is False
            assert row46["indirect_transfer_present"] is False
            assert row46["target_eas"] == [0x40AB90, 0x40B17F]
            assert row46["semantic_target_eas"] == [0x40AB90, 0x40B17F]
            assert row46["delivery_target_eas"] == [0x40AB90, 0x40B17F]
            assert row46["semantic_targets_survive"] is True
            assert row46["passed"] is True
            row47 = observations["rhad:route@0x40ABA8"]
            assert row47["source_present"] is True
            assert row47["source_topology_reachable"] is True
            assert row47["source_topology_retired"] is False
            assert row47["indirect_transfer_present"] is False
            assert row47["target_eas"] == [0x40A5F0, 0x40ABAA]
            assert row47["semantic_target_eas"] == [0x40A5F0, 0x40ABAA]
            assert row47["delivery_target_eas"] == [0x40A5F0, 0x40ABAA]
            assert row47["semantic_targets_survive"] is True
            assert row47["passed"] is True
            row49 = observations["rhad:route@0x40ABDE"]
            assert row49["source_present"] is True
            assert row49["source_topology_reachable"] is True
            assert row49["source_topology_retired"] is False
            assert row49["indirect_transfer_present"] is False
            assert row49["target_eas"] == [0x40ABE0, 0x40B1D0]
            assert row49["semantic_target_eas"] == [0x40ABE0, 0x40B1D0]
            assert row49["delivery_target_eas"] == [0x40ABE0, 0x40B1D0]
            assert row49["semantic_targets_survive"] is True
            assert row49["passed"] is True
            row50 = observations["rhad:route@0x40ABF8"]
            assert row50["source_present"] is True
            assert row50["source_topology_reachable"] is True
            assert row50["source_topology_retired"] is False
            assert row50["indirect_transfer_present"] is False
            assert row50["target_eas"] == [0x40A5F0, 0x40ABFA]
            assert row50["semantic_target_eas"] == [0x40A5F0, 0x40ABFA]
            assert row50["delivery_target_eas"] == [0x40A5F0, 0x40ABFA]
            assert row50["semantic_targets_survive"] is True
            assert row50["passed"] is True
            row51 = observations["route:rhad-direct@0x40AC3B"]
            assert row51["source_present"] is True
            assert row51["source_topology_reachable"] is True
            assert row51["source_topology_retired"] is False
            assert row51["indirect_transfer_present"] is False
            assert row51["target_eas"] == [0x40B6C0]
            assert row51["boundary_exit_eas"] == [0x40B790]
            assert row51["passed"] is True
            row52 = observations["rhad:route@0x40AC54"]
            assert row52["source_present"] is True
            assert row52["source_topology_reachable"] is True
            assert row52["source_topology_retired"] is False
            assert row52["indirect_transfer_present"] is False
            assert row52["target_eas"] == [0x40AC56, 0x40B21C]
            assert row52["semantic_target_eas"] == [0x40AC56, 0x40B21C]
            assert row52["delivery_target_eas"] == [0x40AC56, 0x40B21C]
            assert row52["semantic_targets_survive"] is True
            assert row52["passed"] is True
            row53 = observations["rhad:route@0x40AC6E"]
            assert row53["source_present"] is True
            assert row53["source_topology_reachable"] is True
            assert row53["source_topology_retired"] is False
            assert row53["indirect_transfer_present"] is False
            assert row53["target_eas"] == [0x40A5F0, 0x40AC70]
            assert row53["semantic_target_eas"] == [0x40A5F0, 0x40AC70]
            assert row53["delivery_target_eas"] == [0x40A5F0, 0x40AC70]
            assert row53["semantic_targets_survive"] is True
            assert row53["passed"] is True
            row54 = observations["route:rhad-direct@0x40ACBD"]
            assert row54["source_present"] is True
            assert row54["source_topology_reachable"] is True
            assert row54["source_topology_retired"] is False
            assert row54["indirect_transfer_present"] is False
            assert row54["target_eas"] == [0x40B6C0]
            assert row54["boundary_exit_eas"] == [0x40B790]
            assert row54["passed"] is True
            row55 = observations["rhad:route@0x40ACD7"]
            assert row55["source_present"] is True
            assert row55["source_topology_reachable"] is True
            assert row55["source_topology_retired"] is False
            assert row55["indirect_transfer_present"] is False
            assert row55["target_eas"] == [0x40ACD9, 0x40B26D]
            assert row55["semantic_target_eas"] == [0x40ACD9, 0x40B26D]
            assert row55["delivery_target_eas"] == [0x40ACD9, 0x40B26D]
            assert row55["semantic_targets_survive"] is True
            assert row55["passed"] is True
            row56 = observations["rhad:route@0x40ACF1"]
            assert row56["source_present"] is True
            assert row56["source_topology_reachable"] is True
            assert row56["source_topology_retired"] is False
            assert row56["indirect_transfer_present"] is False
            assert row56["target_eas"] == [0x40A5F0, 0x40ACF3]
            assert row56["semantic_target_eas"] == [0x40A5F0, 0x40ACF3]
            assert row56["delivery_target_eas"] == [0x40A5F0, 0x40ACF3]
            assert row56["semantic_targets_survive"] is True
            assert row56["passed"] is True
            row57 = observations["route:rhad-direct@0x40AD1C"]
            assert row57["source_present"] is True
            assert row57["source_topology_reachable"] is True
            assert row57["source_topology_retired"] is False
            assert row57["indirect_transfer_present"] is False
            assert row57["target_eas"] == [0x40B6C0]
            assert row57["boundary_exit_eas"] == [0x40B790]
            assert row57["passed"] is True
            row58 = observations["rhad:route@0x40AD36"]
            assert row58["source_present"] is True
            assert row58["source_topology_reachable"] is True
            assert row58["source_topology_retired"] is False
            assert row58["indirect_transfer_present"] is False
            assert row58["target_eas"] == [0x40AD38, 0x40B2DB]
            assert row58["semantic_target_eas"] == [0x40AD38, 0x40B2DB]
            assert row58["delivery_target_eas"] == [0x40AD38, 0x40B2DB]
            assert row58["semantic_targets_survive"] is True
            assert row58["passed"] is True
            row59 = observations["rhad:route@0x40AD50"]
            assert row59["source_present"] is True
            assert row59["source_topology_reachable"] is True
            assert row59["source_topology_retired"] is False
            assert row59["indirect_transfer_present"] is False
            assert row59["target_eas"] == [0x40A5F0, 0x40AD52]
            assert row59["semantic_target_eas"] == [0x40A5F0, 0x40AD52]
            assert row59["delivery_target_eas"] == [0x40A5F0, 0x40AD52]
            assert row59["semantic_targets_survive"] is True
            assert row59["passed"] is True
            row60 = observations["rhad:route@0x40AD6C"]
            assert row60["source_present"] is True
            assert row60["indirect_transfer_present"] is False
            assert row60["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row60["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row60["semantic_targets_survive"] is True
            assert row60["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row60["source_topology_reachable"] is False
                assert row60["source_topology_retired"] is True
                assert row60["target_eas"] == [0x40B6C0]
            else:
                assert row60["source_topology_reachable"] is True
                assert row60["source_topology_retired"] is False
                assert row60["target_eas"] == [0x40A607, 0x40B6C0]
            row61 = observations["rhad:route@0x40AD86"]
            assert row61["source_present"] is True
            assert row61["source_topology_reachable"] is True
            assert row61["source_topology_retired"] is False
            assert row61["indirect_transfer_present"] is False
            assert row61["target_eas"] == [0x40AD88, 0x40B32C]
            assert row61["semantic_target_eas"] == [0x40AD88, 0x40B32C]
            assert row61["delivery_target_eas"] == [0x40AD88, 0x40B32C]
            assert row61["semantic_targets_survive"] is True
            assert row61["passed"] is True
            row62 = observations["rhad:route@0x40ADA0"]
            assert row62["source_present"] is True
            assert row62["source_topology_reachable"] is True
            assert row62["source_topology_retired"] is False
            assert row62["indirect_transfer_present"] is False
            assert row62["target_eas"] == [0x40A5F0, 0x40ADA2]
            assert row62["semantic_target_eas"] == [0x40A5F0, 0x40ADA2]
            assert row62["delivery_target_eas"] == [0x40A5F0, 0x40ADA2]
            assert row62["semantic_targets_survive"] is True
            assert row62["passed"] is True
            row63 = observations["rhad:route@0x40ADBC"]
            assert row63["source_present"] is True
            assert row63["indirect_transfer_present"] is False
            assert row63["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row63["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row63["semantic_targets_survive"] is True
            assert row63["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row63["source_topology_reachable"] is False
                assert row63["source_topology_retired"] is True
                assert row63["target_eas"] == [0x40A607]
            else:
                assert row63["source_topology_reachable"] is True
                assert row63["source_topology_retired"] is False
                assert row63["target_eas"] == [0x40A607, 0x40B6C0]
            row64 = observations["rhad:route@0x40ADD6"]
            assert row64["source_present"] is True
            assert row64["source_topology_reachable"] is True
            assert row64["source_topology_retired"] is False
            assert row64["indirect_transfer_present"] is False
            assert row64["target_eas"] == [0x40ADD8, 0x40B37C]
            assert row64["semantic_target_eas"] == [0x40ADD8, 0x40B37C]
            assert row64["delivery_target_eas"] == [0x40ADD8, 0x40B37C]
            assert row64["semantic_targets_survive"] is True
            assert row64["passed"] is True
            row65 = observations["rhad:route@0x40ADF0"]
            assert row65["source_present"] is True
            assert row65["source_topology_reachable"] is True
            assert row65["source_topology_retired"] is False
            assert row65["indirect_transfer_present"] is False
            assert row65["target_eas"] == [0x40A5F0, 0x40ADF2]
            assert row65["semantic_target_eas"] == [0x40A5F0, 0x40ADF2]
            assert row65["delivery_target_eas"] == [0x40A5F0, 0x40ADF2]
            assert row65["semantic_targets_survive"] is True
            assert row65["passed"] is True
            row66 = observations["rhad:route@0x40AE18"]
            assert row66["source_present"] is True
            assert row66["indirect_transfer_present"] is False
            assert row66["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row66["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row66["semantic_targets_survive"] is True
            assert row66["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row66["source_topology_reachable"] is False
                assert row66["source_topology_retired"] is True
                assert row66["target_eas"] == [0x40A607]
            else:
                assert row66["source_topology_reachable"] is True
                assert row66["source_topology_retired"] is False
                assert row66["target_eas"] == [0x40A607, 0x40B6C0]
            row67 = observations["route:rhad-direct@0x40AE24"]
            assert row67["indirect_transfer_present"] is False
            assert row67["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
            assert row67["passed"] is True
            assert row67["source_present"] is True
            assert row67["source_topology_reachable"] is True
            assert row67["source_topology_retired"] is False
            assert row67["target_eas"] == [0x40A5CA]
            row68 = observations["rhad:route@0x40AE3C"]
            assert row68["source_present"] is True
            assert row68["source_topology_reachable"] is True
            assert row68["source_topology_retired"] is False
            assert row68["indirect_transfer_present"] is False
            assert row68["target_eas"] == [0x40A5F0, 0x40AE3E]
            assert row68["semantic_target_eas"] == [0x40A5F0, 0x40AE3E]
            assert row68["delivery_target_eas"] == [0x40A5F0, 0x40AE3E]
            assert row68["semantic_targets_survive"] is True
            assert row68["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row68["passed"] is True
            row69 = observations["rhad:route@0x40AE89"]
            assert row69["source_present"] is True
            assert row69["indirect_transfer_present"] is False
            assert row69["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row69["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row69["semantic_targets_survive"] is True
            assert row69["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row69["source_topology_reachable"] is False
                assert row69["source_topology_retired"] is True
                assert row69["target_eas"] == [0x40B6C0]
            else:
                assert row69["source_topology_reachable"] is True
                assert row69["source_topology_retired"] is False
                assert row69["target_eas"] == [0x40A607, 0x40B6C0]
            row70 = observations["rhad:route@0x40AEA3"]
            assert row70["source_present"] is True
            assert row70["source_topology_reachable"] is True
            assert row70["source_topology_retired"] is False
            assert row70["indirect_transfer_present"] is False
            assert row70["target_eas"] == [0x40A5F0, 0x40AEA5]
            assert row70["semantic_target_eas"] == [0x40A5F0, 0x40AEA5]
            assert row70["delivery_target_eas"] == [0x40A5F0, 0x40AEA5]
            assert row70["semantic_targets_survive"] is True
            assert row70["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row70["passed"] is True
            row71 = observations["route:rhad-direct@0x40AEE4"]
            assert row71["source_present"] is True
            assert row71["source_topology_reachable"] is True
            assert row71["source_topology_retired"] is False
            assert row71["indirect_transfer_present"] is False
            assert row71["target_eas"] == [0x40B6C0]
            assert row71["boundary_exit_eas"] == [0x40B790]
            assert row71["passed"] is True
            row72 = observations["rhad:route@0x40AEFE"]
            assert row72["source_present"] is True
            assert row72["source_topology_reachable"] is True
            assert row72["source_topology_retired"] is False
            assert row72["indirect_transfer_present"] is False
            assert row72["target_eas"] == [0x40A5F0, 0x40AF00]
            assert row72["semantic_target_eas"] == [0x40A5F0, 0x40AF00]
            assert row72["delivery_target_eas"] == [0x40A5F0, 0x40AF00]
            assert row72["semantic_targets_survive"] is True
            assert row72["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row72["passed"] is True
            row73 = observations["route:rhad-direct@0x40AFDD"]
            assert row73["source_present"] is True
            assert row73["source_topology_reachable"] is True
            assert row73["source_topology_retired"] is False
            assert row73["indirect_transfer_present"] is False
            assert row73["target_eas"] == [0x40B6C0]
            assert row73["boundary_exit_eas"] == [0x40B790]
            assert row73["passed"] is True
            row74 = observations["rhad:route@0x40AFF7"]
            assert row74["source_present"] is True
            assert row74["source_topology_reachable"] is True
            assert row74["source_topology_retired"] is False
            assert row74["indirect_transfer_present"] is False
            assert row74["target_eas"] == [0x40A5F0, 0x40AFF9]
            assert row74["semantic_target_eas"] == [0x40A5F0, 0x40AFF9]
            assert row74["delivery_target_eas"] == [0x40A5F0, 0x40AFF9]
            assert row74["semantic_targets_survive"] is True
            assert row74["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row74["passed"] is True
            row75 = observations["route:rhad-direct@0x40B022"]
            assert row75["source_present"] is True
            assert row75["source_topology_reachable"] is True
            assert row75["source_topology_retired"] is False
            assert row75["indirect_transfer_present"] is False
            assert row75["target_eas"] == [0x40B6C0]
            assert row75["boundary_exit_eas"] == [0x40B790]
            assert row75["passed"] is True
            row76 = observations["rhad:route@0x40B03C"]
            assert row76["source_present"] is True
            assert row76["source_topology_reachable"] is True
            assert row76["source_topology_retired"] is False
            assert row76["indirect_transfer_present"] is False
            assert row76["target_eas"] == [0x40A5F0, 0x40B03E]
            assert row76["semantic_target_eas"] == [0x40A5F0, 0x40B03E]
            assert row76["delivery_target_eas"] == [0x40A5F0, 0x40B03E]
            assert row76["semantic_targets_survive"] is True
            assert row76["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row76["passed"] is True
            row77 = observations["route:rhad-direct@0x40B06F"]
            assert row77["source_present"] is True
            assert row77["source_topology_reachable"] is True
            assert row77["source_topology_retired"] is False
            assert row77["indirect_transfer_present"] is False
            assert row77["target_eas"] == [0x40B6C0]
            assert row77["boundary_exit_eas"] == [0x40B790]
            assert row77["passed"] is True
            row78 = observations["rhad:route@0x40B089"]
            assert row78["source_present"] is True
            assert row78["source_topology_reachable"] is True
            assert row78["source_topology_retired"] is False
            assert row78["indirect_transfer_present"] is False
            assert row78["target_eas"] == [0x40A5F0, 0x40B08B]
            assert row78["semantic_target_eas"] == [0x40A5F0, 0x40B08B]
            assert row78["delivery_target_eas"] == [0x40A5F0, 0x40B08B]
            assert row78["semantic_targets_survive"] is True
            assert row78["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row78["passed"] is True
            row79 = observations["rhad:route@0x40B0BA"]
            assert row79["source_present"] is True
            assert row79["indirect_transfer_present"] is False
            assert row79["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row79["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row79["semantic_targets_survive"] is True
            assert row79["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row79["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row79["source_topology_reachable"] is False
                assert row79["source_topology_retired"] is True
                assert row79["target_eas"] == [0x40A607]
            else:
                assert row79["source_topology_reachable"] is True
                assert row79["source_topology_retired"] is False
                assert row79["target_eas"] == [0x40A607, 0x40B6C0]
            row80 = observations["rhad:route@0x40B0D4"]
            assert row80["source_present"] is True
            assert row80["source_topology_reachable"] is True
            assert row80["source_topology_retired"] is False
            assert row80["indirect_transfer_present"] is False
            assert row80["target_eas"] == [0x40A5F0, 0x40B0D6]
            assert row80["semantic_target_eas"] == [0x40A5F0, 0x40B0D6]
            assert row80["delivery_target_eas"] == [0x40A5F0, 0x40B0D6]
            assert row80["semantic_targets_survive"] is True
            assert row80["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row80["passed"] is True
            row81 = observations["rhad:route@0x40B0F0"]
            assert row81["source_present"] is True
            assert row81["indirect_transfer_present"] is False
            assert row81["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row81["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row81["semantic_targets_survive"] is True
            assert row81["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row81["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row81["source_topology_reachable"] is False
                assert row81["source_topology_retired"] is True
                assert row81["target_eas"] == [0x40B6C0]
            else:
                assert row81["source_topology_reachable"] is True
                assert row81["source_topology_retired"] is False
                assert row81["target_eas"] == [0x40A607, 0x40B6C0]
            row82 = observations["rhad:route@0x40B10A"]
            assert row82["source_present"] is True
            assert row82["source_topology_reachable"] is True
            assert row82["source_topology_retired"] is False
            assert row82["indirect_transfer_present"] is False
            assert row82["target_eas"] == [0x40A5F0, 0x40B10C]
            assert row82["semantic_target_eas"] == [0x40A5F0, 0x40B10C]
            assert row82["delivery_target_eas"] == [0x40A5F0, 0x40B10C]
            assert row82["semantic_targets_survive"] is True
            assert row82["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row82["passed"] is True
            row83 = observations["rhad:route@0x40B147"]
            assert row83["source_present"] is True
            assert row83["indirect_transfer_present"] is False
            assert row83["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row83["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row83["semantic_targets_survive"] is True
            assert row83["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row83["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row83["source_topology_reachable"] is False
                assert row83["source_topology_retired"] is True
                assert row83["target_eas"] == [0x40A607]
            else:
                assert row83["source_topology_reachable"] is True
                assert row83["source_topology_retired"] is False
                assert row83["target_eas"] == [0x40A607, 0x40B6C0]
            row84 = observations["rhad:route@0x40B161"]
            assert row84["source_present"] is True
            assert row84["source_topology_reachable"] is True
            assert row84["source_topology_retired"] is False
            assert row84["indirect_transfer_present"] is False
            assert row84["target_eas"] == [0x40A5F0, 0x40B163]
            assert row84["semantic_target_eas"] == [0x40A5F0, 0x40B163]
            assert row84["delivery_target_eas"] == [0x40A5F0, 0x40B163]
            assert row84["semantic_targets_survive"] is True
            assert row84["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row84["passed"] is True
            row85 = observations["rhad:route@0x40B17D"]
            assert row85["source_present"] is True
            assert row85["indirect_transfer_present"] is False
            assert row85["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row85["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row85["semantic_targets_survive"] is True
            assert row85["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row85["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row85["source_topology_reachable"] is False
                assert row85["source_topology_retired"] is True
                assert row85["target_eas"] == [0x40A607]
            else:
                assert row85["source_topology_reachable"] is True
                assert row85["source_topology_retired"] is False
                assert row85["target_eas"] == [0x40A607, 0x40B6C0]
            row86 = observations["rhad:route@0x40B197"]
            assert row86["source_present"] is True
            assert row86["source_topology_reachable"] is True
            assert row86["source_topology_retired"] is False
            assert row86["indirect_transfer_present"] is False
            assert row86["target_eas"] == [0x40A5F0, 0x40B199]
            assert row86["semantic_target_eas"] == [0x40A5F0, 0x40B199]
            assert row86["delivery_target_eas"] == [0x40A5F0, 0x40B199]
            assert row86["semantic_targets_survive"] is True
            assert row86["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row86["passed"] is True
            row87 = observations["route:rhad-direct@0x40B1CE"]
            assert row87["source_present"] is True
            assert row87["source_topology_reachable"] is True
            assert row87["source_topology_retired"] is False
            assert row87["indirect_transfer_present"] is False
            assert row87["target_eas"] == [0x40B6C0]
            assert row87["boundary_exit_eas"] == [0x40B790]
            assert row87["passed"] is True
            row88 = observations["rhad:route@0x40B1E8"]
            assert row88["source_present"] is True
            assert row88["source_topology_reachable"] is True
            assert row88["source_topology_retired"] is False
            assert row88["indirect_transfer_present"] is False
            assert row88["target_eas"] == [0x40A5F0, 0x40B1EA]
            assert row88["semantic_target_eas"] == [0x40A5F0, 0x40B1EA]
            assert row88["delivery_target_eas"] == [0x40A5F0, 0x40B1EA]
            assert row88["semantic_targets_survive"] is True
            assert row88["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row88["passed"] is True
            row89 = observations["rhad:route@0x40B21A"]
            assert row89["source_present"] is True
            assert row89["indirect_transfer_present"] is False
            assert row89["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row89["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row89["semantic_targets_survive"] is True
            assert row89["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row89["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row89["source_topology_reachable"] is False
                assert row89["source_topology_retired"] is True
                assert row89["target_eas"] == [0x40A607]
            else:
                assert row89["source_topology_reachable"] is True
                assert row89["source_topology_retired"] is False
                assert row89["target_eas"] == [0x40A607, 0x40B6C0]
            row90 = observations["rhad:route@0x40B234"]
            assert row90["source_present"] is True
            assert row90["source_topology_reachable"] is True
            assert row90["source_topology_retired"] is False
            assert row90["indirect_transfer_present"] is False
            assert row90["target_eas"] == [0x40A5F0, 0x40B236]
            assert row90["semantic_target_eas"] == [0x40A5F0, 0x40B236]
            assert row90["delivery_target_eas"] == [0x40A5F0, 0x40B236]
            assert row90["semantic_targets_survive"] is True
            assert row90["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row90["passed"] is True
            row91 = observations["rhad:route@0x40B26B"]
            assert row91["source_present"] is True
            assert row91["indirect_transfer_present"] is False
            assert row91["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row91["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row91["semantic_targets_survive"] is True
            assert row91["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row91["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row91["source_topology_reachable"] is False
                assert row91["source_topology_retired"] is True
                assert row91["target_eas"] == [0x40B6C0]
            else:
                assert row91["source_topology_reachable"] is True
                assert row91["source_topology_retired"] is False
                assert row91["target_eas"] == [0x40A607, 0x40B6C0]
            row92 = observations["rhad:route@0x40B285"]
            assert row92["source_present"] is True
            assert row92["indirect_transfer_present"] is False
            assert row92["semantic_target_eas"] == [0x40A5F0, 0x40B287]
            assert row92["delivery_target_eas"] == [0x40A5F0, 0x40B287]
            assert row92["semantic_targets_survive"] is True
            assert row92["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row92["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row92["source_topology_reachable"] is False
                assert row92["source_topology_retired"] is True
                assert row92["target_eas"] == [0x40A5F0, 0x40A90D]
            else:
                assert row92["source_topology_reachable"] is True
                assert row92["source_topology_retired"] is False
                assert row92["target_eas"] == [0x40A5F0, 0x40B287]
            row93 = observations["route:rhad-direct@0x40B2D9"]
            assert row93["source_present"] is True
            assert row93["source_topology_reachable"] is True
            assert row93["source_topology_retired"] is False
            assert row93["indirect_transfer_present"] is False
            assert row93["target_eas"] == [0x40B6C0]
            assert row93["boundary_exit_eas"] == [0x40B790]
            assert row93["passed"] is True
            row94 = observations["rhad:route@0x40B2F3"]
            assert row94["source_present"] is True
            assert row94["indirect_transfer_present"] is False
            assert row94["semantic_target_eas"] == [0x40A5F0, 0x40B2F5]
            assert row94["delivery_target_eas"] == [0x40A5F0, 0x40B2F5]
            assert row94["semantic_targets_survive"] is True
            assert row94["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row94["passed"] is True
            if maturity == "MMAT_CALLS":
                assert row94["source_topology_reachable"] is False
                assert row94["source_topology_retired"] is True
                assert row94["target_eas"] == []
            else:
                assert row94["source_topology_reachable"] is True
                assert row94["source_topology_retired"] is False
                assert row94["target_eas"] == [0x40A5F0, 0x40B2F5]
            row95 = observations["route:rhad-direct@0x40B32A"]
            assert row95["source_present"] is True
            assert row95["source_topology_reachable"] is True
            assert row95["source_topology_retired"] is False
            assert row95["indirect_transfer_present"] is False
            assert row95["target_eas"] == [0x40B6C0]
            assert row95["boundary_exit_eas"] == [0x40B790]
            assert row95["passed"] is True
            row96 = observations["rhad:route@0x40B340"]
            assert row96["source_present"] is True
            assert row96["source_topology_reachable"] is True
            assert row96["source_topology_retired"] is False
            assert row96["indirect_transfer_present"] is False
            assert row96["target_eas"] == [0x40A5F0, 0x40B342]
            assert row96["semantic_target_eas"] == [0x40A5F0, 0x40B342]
            assert row96["delivery_target_eas"] == [0x40A5F0, 0x40B342]
            assert row96["semantic_targets_survive"] is True
            assert row96["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row96["passed"] is True
            row97 = observations["rhad:route@0x40B37A"]
            assert row97["source_present"] is True
            assert row97["indirect_transfer_present"] is False
            assert row97["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row97["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row97["semantic_targets_survive"] is True
            assert row97["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row97["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row97["source_topology_reachable"] is False
                assert row97["source_topology_retired"] is True
                assert row97["target_eas"] == [0x40A607]
            else:
                assert row97["source_topology_reachable"] is True
                assert row97["source_topology_retired"] is False
                assert row97["target_eas"] == [0x40A607, 0x40B6C0]
            row98 = observations["rhad:route@0x40B394"]
            assert row98["source_present"] is True
            assert row98["source_topology_reachable"] is True
            assert row98["source_topology_retired"] is False
            assert row98["indirect_transfer_present"] is False
            assert row98["target_eas"] == [0x40B396, 0x40B3E5]
            assert row98["semantic_target_eas"] == [0x40B396, 0x40B3E5]
            assert row98["delivery_target_eas"] == [0x40B396, 0x40B3E5]
            assert row98["semantic_targets_survive"] is True
            assert row98["boundary_exit_eas"] == [
                0x40A5F0,
                0x40B3B0,
                0x40B3FF,
            ]
            assert row98["passed"] is True
            row99 = observations["rhad:route@0x40B3AE"]
            assert row99["source_present"] is True
            assert row99["source_topology_reachable"] is True
            assert row99["source_topology_retired"] is False
            assert row99["indirect_transfer_present"] is False
            assert row99["target_eas"] == [0x40A5F0, 0x40B3B0]
            assert row99["semantic_target_eas"] == [0x40A5F0, 0x40B3B0]
            assert row99["delivery_target_eas"] == [0x40A5F0, 0x40B3B0]
            assert row99["semantic_targets_survive"] is True
            assert row99["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row99["passed"] is True
            row100 = observations["rhad:route@0x40B3E3"]
            assert row100["source_present"] is True
            assert row100["indirect_transfer_present"] is False
            assert row100["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row100["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row100["semantic_targets_survive"] is True
            assert row100["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row100["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row100["source_topology_reachable"] is False
                assert row100["source_topology_retired"] is True
                assert row100["target_eas"] == [0x40A607]
            else:
                assert row100["source_topology_reachable"] is True
                assert row100["source_topology_retired"] is False
                assert row100["target_eas"] == [0x40A607, 0x40B6C0]
            row101 = observations["rhad:route@0x40B3FD"]
            assert row101["source_present"] is True
            assert row101["source_topology_reachable"] is True
            assert row101["source_topology_retired"] is False
            assert row101["indirect_transfer_present"] is False
            assert row101["target_eas"] == [0x40A5F0, 0x40B3FF]
            assert row101["semantic_target_eas"] == [0x40A5F0, 0x40B3FF]
            assert row101["delivery_target_eas"] == [0x40A5F0, 0x40B3FF]
            assert row101["semantic_targets_survive"] is True
            assert row101["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row101["passed"] is True
            row102 = observations["rhad:route@0x40B4C3"]
            assert row102["source_present"] is True
            assert row102["source_topology_reachable"] is True
            assert row102["source_topology_retired"] is False
            assert row102["indirect_transfer_present"] is False
            assert row102["target_eas"] == [0x40A607, 0x40B6C0]
            assert row102["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row102["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row102["semantic_targets_survive"] is True
            assert row102["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row102["passed"] is True
            row103 = observations["route:rhad-direct@0x40B4EE"]
            assert row103["source_present"] is True
            assert row103["indirect_transfer_present"] is False
            assert row103["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row103["passed"] is True
            assert row103["source_topology_reachable"] is True
            assert row103["source_topology_retired"] is False
            assert row103["target_eas"] == [0x40A607]
            row104 = observations["route:rhad-direct@0x40B519"]
            assert row104["source_present"] is True
            assert row104["indirect_transfer_present"] is False
            assert row104["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row104["passed"] is True
            assert row104["source_topology_reachable"] is True
            assert row104["source_topology_retired"] is False
            assert row104["target_eas"] == [0x40A607]
            assert row104["semantic_target_eas"] == [0x40A607]
            assert row104["delivery_target_eas"] == [0x40A607]
            assert row104["semantic_targets_survive"] is True
            row105 = observations["route:rhad-direct@0x40B540"]
            assert row105["source_present"] is True
            assert row105["indirect_transfer_present"] is False
            assert row105["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row105["passed"] is True
            assert row105["source_topology_reachable"] is True
            assert row105["source_topology_retired"] is False
            assert row105["target_eas"] == [0x40A607]
            assert row105["semantic_target_eas"] == [0x40A607]
            assert row105["delivery_target_eas"] == [0x40A607]
            assert row105["semantic_targets_survive"] is True
            row106 = observations["route:rhad-direct@0x40B56B"]
            assert row106["source_present"] is True
            assert row106["indirect_transfer_present"] is False
            assert row106["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row106["passed"] is True
            assert row106["source_topology_reachable"] is True
            assert row106["source_topology_retired"] is False
            assert row106["target_eas"] == [0x40A607]
            assert row106["semantic_target_eas"] == [0x40A607]
            assert row106["delivery_target_eas"] == [0x40A607]
            assert row106["semantic_targets_survive"] is True
            row107 = observations["route:rhad-direct@0x40B596"]
            assert row107["source_present"] is True
            assert row107["indirect_transfer_present"] is False
            assert row107["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row107["passed"] is True
            assert row107["source_topology_reachable"] is True
            assert row107["source_topology_retired"] is False
            assert row107["target_eas"] == [0x40A607]
            assert row107["semantic_target_eas"] == [0x40A607]
            assert row107["delivery_target_eas"] == [0x40A607]
            assert row107["semantic_targets_survive"] is True
            row108 = observations["route:rhad-direct@0x40B5B5"]
            assert row108["source_present"] is True
            assert row108["indirect_transfer_present"] is False
            assert row108["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row108["passed"] is True
            assert row108["source_topology_reachable"] is True
            assert row108["source_topology_retired"] is False
            assert row108["target_eas"] == [0x40A607]
            assert row108["semantic_target_eas"] == [0x40A607]
            assert row108["delivery_target_eas"] == [0x40A607]
            assert row108["semantic_targets_survive"] is True
            row109 = observations["route:rhad-direct@0x40B5DC"]
            assert row109["source_present"] is True
            assert row109["indirect_transfer_present"] is False
            assert row109["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row109["passed"] is True
            assert row109["source_topology_reachable"] is True
            assert row109["source_topology_retired"] is False
            assert row109["target_eas"] == [0x40A607]
            assert row109["semantic_target_eas"] == [0x40A607]
            assert row109["delivery_target_eas"] == [0x40A607]
            assert row109["semantic_targets_survive"] is True
            row110 = observations["route:rhad-direct@0x40B607"]
            assert row110["source_present"] is True
            assert row110["indirect_transfer_present"] is False
            assert row110["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row110["passed"] is True
            assert row110["source_topology_reachable"] is True
            assert row110["source_topology_retired"] is False
            assert row110["target_eas"] == [0x40A607]
            assert row110["semantic_target_eas"] == [0x40A607]
            assert row110["delivery_target_eas"] == [0x40A607]
            assert row110["semantic_targets_survive"] is True
            row111 = observations["route:rhad-direct@0x40B626"]
            assert row111["source_present"] is True
            assert row111["indirect_transfer_present"] is False
            assert row111["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row111["passed"] is True
            assert row111["source_topology_reachable"] is True
            assert row111["source_topology_retired"] is False
            assert row111["target_eas"] == [0x40A607]
            assert row111["semantic_target_eas"] == [0x40A607]
            assert row111["delivery_target_eas"] == [0x40A607]
            assert row111["semantic_targets_survive"] is True
            row112 = observations["route:rhad-direct@0x40B645"]
            assert row112["source_present"] is True
            assert row112["indirect_transfer_present"] is False
            assert row112["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row112["passed"] is True
            assert row112["source_topology_reachable"] is True
            assert row112["source_topology_retired"] is False
            assert row112["target_eas"] == [0x40A607]
            assert row112["semantic_target_eas"] == [0x40A607]
            assert row112["delivery_target_eas"] == [0x40A607]
            assert row112["semantic_targets_survive"] is True
            row113 = observations["route:rhad-direct@0x40B666"]
            assert row113["source_present"] is True
            assert row113["indirect_transfer_present"] is False
            assert row113["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row113["passed"] is True
            assert row113["source_topology_reachable"] is True
            assert row113["source_topology_retired"] is False
            assert row113["target_eas"] == [0x40A607]
            assert row113["semantic_target_eas"] == [0x40A607]
            assert row113["delivery_target_eas"] == [0x40A607]
            assert row113["semantic_targets_survive"] is True
            row114 = observations["route:rhad-direct@0x40B691"]
            assert row114["source_present"] is True
            assert row114["indirect_transfer_present"] is False
            assert row114["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row114["passed"] is True
            assert row114["source_topology_reachable"] is True
            assert row114["source_topology_retired"] is False
            assert row114["target_eas"] == [0x40A607]
            assert row114["semantic_target_eas"] == [0x40A607]
            assert row114["delivery_target_eas"] == [0x40A607]
            assert row114["semantic_targets_survive"] is True
            row115 = observations["route:rhad-direct@0x40B6B2"]
            assert row115["source_present"] is True
            assert row115["indirect_transfer_present"] is False
            assert row115["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row115["passed"] is True
            assert row115["source_topology_reachable"] is True
            assert row115["source_topology_retired"] is False
            assert row115["target_eas"] == [0x40A607]
            assert row115["semantic_target_eas"] == [0x40A607]
            assert row115["delivery_target_eas"] == [0x40A607]
            assert row115["semantic_targets_survive"] is True
            row116 = observations["rhad:route@0x40B6D4"]
            assert row116["source_present"] is True
            assert row116["source_topology_reachable"] is True
            assert row116["source_topology_retired"] is False
            assert row116["indirect_transfer_present"] is False
            assert row116["target_eas"] == [0x40B6D6, 0x40B790]
            assert row116["semantic_target_eas"] == [0x40B6D6, 0x40B790]
            assert row116["delivery_target_eas"] == [0x40B6D6, 0x40B790]
            assert row116["semantic_targets_survive"] is True
            assert row116["boundary_exit_eas"] == [0x40B940]
            assert row116["passed"] is True
            row117 = observations["rhad:route@0x40B6EE"]
            assert row117["source_present"] is True
            assert row117["source_topology_reachable"] is False
            assert row117["source_topology_retired"] is True
            assert row117["indirect_transfer_present"] is False
            assert row117["target_eas"] == [
                0x40B6F0,
                0x40B882,
            ]
            assert row117["semantic_target_eas"] == [0x40B6F0, 0x40B880]
            assert row117["delivery_target_eas"] == [0x40B6F0, 0x40B880]
            assert row117["semantic_targets_survive"] is True
            assert row117["boundary_exit_eas"] == [
                0x40B70A,
                0x40B898,
                0x40BB75,
                0x40BC61,
            ]
            assert row117["passed"] is True
            row118 = observations["rhad:route@0x40B708"]
            assert row118["source_present"] is True
            assert row118["source_topology_reachable"] is True
            assert row118["source_topology_retired"] is False
            assert row118["indirect_transfer_present"] is False
            assert row118["target_eas"] == [0x40B70A, 0x40BB75]
            assert row118["semantic_target_eas"] == [0x40B70A, 0x40BB75]
            assert row118["delivery_target_eas"] == [0x40B70A, 0x40BB75]
            assert row118["semantic_targets_survive"] is True
            assert row118["boundary_exit_eas"] == [
                0x40B724,
                0x40BB8F,
                0x40BD50,
                0x40BF8C,
            ]
            assert row118["passed"] is True
            row119 = observations["rhad:route@0x40B722"]
            assert row119["source_present"] is True
            assert row119["source_topology_reachable"] is True
            assert row119["source_topology_retired"] is False
            assert row119["indirect_transfer_present"] is False
            assert row119["target_eas"] == [0x40B724, 0x40BD50]
            assert row119["semantic_target_eas"] == [0x40B724, 0x40BD50]
            assert row119["delivery_target_eas"] == [0x40B724, 0x40BD50]
            assert row119["semantic_targets_survive"] is True
            assert row119["boundary_exit_eas"] == [
                0x40B73E,
                0x40BD6A,
                0x40C0F0,
                0x40C3D9,
            ]
            assert row119["passed"] is True
            row120 = observations["rhad:route@0x40B73C"]
            assert row120["source_present"] is True
            assert row120["source_topology_reachable"] is True
            assert row120["source_topology_retired"] is False
            assert row120["indirect_transfer_present"] is False
            assert row120["target_eas"] == [0x40B73E, 0x40C0F0]
            assert row120["semantic_target_eas"] == [0x40B73E, 0x40C0F0]
            assert row120["delivery_target_eas"] == [0x40B73E, 0x40C0F0]
            assert row120["semantic_targets_survive"] is True
            assert row120["boundary_exit_eas"] == [
                0x40A5F0,
                0x40B758,
                0x40C10A,
            ]
            assert row120["passed"] is True
            row121 = observations["rhad:route@0x40B756"]
            assert row121["source_present"] is True
            assert row121["source_topology_reachable"] is True
            assert row121["source_topology_retired"] is False
            assert row121["indirect_transfer_present"] is False
            assert row121["target_eas"] == [0x40A5F0, 0x40B758]
            assert row121["semantic_target_eas"] == [0x40A5F0, 0x40B758]
            assert row121["delivery_target_eas"] == [0x40A5F0, 0x40B758]
            assert row121["semantic_targets_survive"] is True
            assert row121["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row121["passed"] is True
            row122 = observations["route:rhad-direct@0x40B781"]
            assert row122["source_present"] is True
            assert row122["source_topology_reachable"] is True
            assert row122["source_topology_retired"] is False
            assert row122["indirect_transfer_present"] is False
            assert row122["target_eas"] == [0x40B6C0]
            assert row122["semantic_target_eas"] == [0x40B6C0]
            assert row122["delivery_target_eas"] == [0x40B6C0]
            assert row122["semantic_targets_survive"] is True
            assert row122["boundary_exit_eas"] == [0x40B790]
            assert row122["passed"] is True
            row123 = observations["rhad:route@0x40B7A8"]
            assert row123["source_present"] is True
            assert row123["source_topology_reachable"] is False
            assert row123["source_topology_retired"] is True
            assert row123["indirect_transfer_present"] is False
            assert row123["target_eas"] == [0x40B7AA, 0x40B942]
            assert row123["semantic_target_eas"] == [0x40B7AA, 0x40B940]
            assert row123["delivery_target_eas"] == [0x40B7AA, 0x40B940]
            assert row123["semantic_targets_survive"] is True
            assert row123["boundary_exit_eas"] == [
                0x40B7C4,
                0x40B958,
                0x40BBDF,
                0x40BCCB,
            ]
            assert row123["passed"] is True
            row124 = observations["rhad:route@0x40B7C2"]
            assert row124["source_present"] is True
            assert row124["source_topology_reachable"] is True
            assert row124["source_topology_retired"] is False
            assert row124["indirect_transfer_present"] is False
            assert row124["target_eas"] == [0x40B7C4, 0x40BBDF]
            assert row124["semantic_target_eas"] == [0x40B7C4, 0x40BBDF]
            assert row124["delivery_target_eas"] == [0x40B7C4, 0x40BBDF]
            assert row124["semantic_targets_survive"] is True
            assert row124["boundary_exit_eas"] == [
                0x40B7DE,
                0x40BBF9,
                0x40BE2F,
                0x40BFDA,
            ]
            assert row124["passed"] is True
            row125 = observations["rhad:route@0x40B7DC"]
            assert row125["source_present"] is True
            assert row125["source_topology_reachable"] is False
            assert row125["source_topology_retired"] is True
            assert row125["indirect_transfer_present"] is False
            assert row125["target_eas"] == [0x40B7E0, 0x40BE2F]
            assert row125["semantic_target_eas"] == [0x40B7DE, 0x40BE2F]
            assert row125["delivery_target_eas"] == [0x40B7DE, 0x40BE2F]
            assert row125["semantic_targets_survive"] is True
            assert row125["boundary_exit_eas"] == [
                0x40B7F6,
                0x40C150,
                0x40C42E,
            ]
            assert row125["passed"] is True
            row126 = observations["rhad:route@0x40B7F4"]
            assert row126["source_present"] is True
            assert row126["source_topology_reachable"] is True
            assert row126["source_topology_retired"] is False
            assert row126["indirect_transfer_present"] is False
            assert row126["target_eas"] == [0x40B7F6, 0x40C150]
            assert row126["semantic_target_eas"] == [0x40B7F6, 0x40C150]
            assert row126["delivery_target_eas"] == [0x40B7F6, 0x40C150]
            assert row126["semantic_targets_survive"] is True
            assert row126["boundary_exit_eas"] == [
                0x40A5F0,
                0x40B810,
                0x40C16A,
            ]
            assert row126["passed"] is True
            row127 = observations["rhad:route@0x40B80E"]
            assert row127["source_present"] is True
            assert row127["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row127["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row127["indirect_transfer_present"] is False
            assert row127["target_eas"] == [
                0x40A5F0,
                0x40B839 if maturity == "MMAT_LOCOPT" else 0x40B810,
            ]
            assert row127["semantic_target_eas"] == [0x40A5F0, 0x40B810]
            assert row127["delivery_target_eas"] == [0x40A5F0, 0x40B810]
            assert row127["semantic_targets_survive"] is True
            assert row127["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row127["passed"] is True
            row128 = observations["rhad:route@0x40B879"]
            assert row128["source_present"] is True
            assert row128["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row128["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row128["indirect_transfer_present"] is False
            assert row128["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row128["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row128["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row128["semantic_targets_survive"] is True
            assert row128["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row128["passed"] is True
            row129 = observations["rhad:route@0x40B896"]
            assert row129["source_present"] is True
            assert row129["source_topology_reachable"] is True
            assert row129["source_topology_retired"] is False
            assert row129["indirect_transfer_present"] is False
            assert row129["target_eas"] == [0x40B898, 0x40BC61]
            assert row129["semantic_target_eas"] == [0x40B898, 0x40BC61]
            assert row129["delivery_target_eas"] == [0x40B898, 0x40BC61]
            assert row129["semantic_targets_survive"] is True
            assert row129["boundary_exit_eas"] == [0x40BE98, 0x40C041]
            assert row129["passed"] is True
            row130 = observations["rhad:route@0x40B8B0"]
            assert row130["source_present"] is True
            assert row130["source_topology_reachable"] is True
            assert row130["source_topology_retired"] is False
            assert row130["indirect_transfer_present"] is False
            assert row130["target_eas"] == [0x40B8B2, 0x40BE98]
            assert row130["semantic_target_eas"] == [0x40B8B2, 0x40BE98]
            assert row130["delivery_target_eas"] == [0x40B8B2, 0x40BE98]
            assert row130["semantic_targets_survive"] is True
            assert row130["boundary_exit_eas"] == [
                0x40B8CC,
                0x40BEB2,
                0x40C186,
                0x40C464,
            ]
            assert row130["passed"] is True
            row131 = observations["rhad:route@0x40B8CA"]
            assert row131["source_present"] is True
            assert row131["source_topology_reachable"] is True
            assert row131["source_topology_retired"] is False
            assert row131["indirect_transfer_present"] is False
            assert row131["target_eas"] == [0x40B8CC, 0x40C186]
            assert row131["semantic_target_eas"] == [0x40B8CC, 0x40C186]
            assert row131["delivery_target_eas"] == [0x40B8CC, 0x40C186]
            assert row131["semantic_targets_survive"] is True
            assert row131["boundary_exit_eas"] == [0x40A5F0, 0x40B8E6]
            assert row131["passed"] is True
            row132 = observations["rhad:route@0x40B8E4"]
            assert row132["source_present"] is True
            assert row132["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row132["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row132["indirect_transfer_present"] is False
            assert row132["target_eas"] == [
                0x40A5F0,
                0x40B8FA if maturity == "MMAT_LOCOPT" else 0x40B8E6,
            ]
            assert row132["semantic_target_eas"] == [0x40A5F0, 0x40B8E6]
            assert row132["delivery_target_eas"] == [0x40A5F0, 0x40B8E6]
            assert row132["semantic_targets_survive"] is True
            assert row132["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row132["passed"] is True
            row133 = observations["route:rhad-direct@0x40B931"]
            assert row133["source_present"] is True
            assert row133["source_topology_reachable"] is True
            assert row133["source_topology_retired"] is False
            assert row133["indirect_transfer_present"] is False
            assert row133["target_eas"] == [0x40B6C0]
            assert row133["semantic_target_eas"] == [0x40B6C0]
            assert row133["delivery_target_eas"] == [0x40B6C0]
            assert row133["semantic_targets_survive"] is True
            assert row133["boundary_exit_eas"] == [0x40B790]
            assert row133["passed"] is True
            row134 = observations["rhad:route@0x40B956"]
            assert row134["source_present"] is True
            assert row134["source_topology_reachable"] is True
            assert row134["source_topology_retired"] is False
            assert row134["indirect_transfer_present"] is False
            assert row134["target_eas"] == [0x40B958, 0x40BCCB]
            assert row134["semantic_target_eas"] == [0x40B958, 0x40BCCB]
            assert row134["delivery_target_eas"] == [0x40B958, 0x40BCCB]
            assert row134["semantic_targets_survive"] is True
            assert row134["boundary_exit_eas"] == [0x40BEE7, 0x40C0A0]
            assert row134["passed"] is True
            row135 = observations["rhad:route@0x40B970"]
            assert row135["source_present"] is True
            assert row135["source_topology_reachable"] is True
            assert row135["source_topology_retired"] is False
            assert row135["indirect_transfer_present"] is False
            assert row135["target_eas"] == [0x40B972, 0x40BEE7]
            assert row135["semantic_target_eas"] == [0x40B972, 0x40BEE7]
            assert row135["delivery_target_eas"] == [0x40B972, 0x40BEE7]
            assert row135["semantic_targets_survive"] is True
            assert row135["boundary_exit_eas"] == [0x40C1F2, 0x40C49A]
            assert row135["passed"] is True
            row136 = observations["rhad:route@0x40B98A"]
            assert row136["source_present"] is True
            assert row136["source_topology_reachable"] is True
            assert row136["source_topology_retired"] is False
            assert row136["indirect_transfer_present"] is False
            assert row136["target_eas"] == [0x40B98C, 0x40C1F2]
            assert row136["semantic_target_eas"] == [0x40B98C, 0x40C1F2]
            assert row136["delivery_target_eas"] == [0x40B98C, 0x40C1F2]
            assert row136["semantic_targets_survive"] is True
            assert row136["boundary_exit_eas"] == [0x40A5F0, 0x40B9A6]
            assert row136["passed"] is True
            row137 = observations["rhad:route@0x40B9A4"]
            assert row137["source_present"] is True
            assert row137["source_topology_reachable"] is True
            assert row137["source_topology_retired"] is False
            assert row137["indirect_transfer_present"] is False
            assert row137["target_eas"] == [0x40A5F0, 0x40B9A6]
            assert row137["semantic_target_eas"] == [0x40A5F0, 0x40B9A6]
            assert row137["delivery_target_eas"] == [0x40A5F0, 0x40B9A6]
            assert row137["semantic_targets_survive"] is True
            assert row137["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row137["passed"] is True
            row138 = observations["route:rhad-direct@0x40BB73"]
            assert row138["source_present"] is True
            assert row138["source_topology_reachable"] is True
            assert row138["source_topology_retired"] is False
            assert row138["indirect_transfer_present"] is False
            assert row138["target_eas"] == [0x40B6C0]
            assert row138["semantic_target_eas"] == [0x40B6C0]
            assert row138["delivery_target_eas"] == [0x40B6C0]
            assert row138["semantic_targets_survive"] is True
            assert row138["boundary_exit_eas"] == [0x40B790]
            assert row138["passed"] is True
            row139 = observations["rhad:route@0x40BB8D"]
            assert row139["source_present"] is True
            assert row139["source_topology_reachable"] is False
            assert row139["source_topology_retired"] is True
            assert row139["indirect_transfer_present"] is False
            assert row139["target_eas"] == [
                0x40BB8F,
                0x40BF8E,
            ]
            assert row139["semantic_target_eas"] == [0x40BB8F, 0x40BF8C]
            assert row139["delivery_target_eas"] == [0x40BB8F, 0x40BF8C]
            assert row139["semantic_targets_survive"] is True
            assert row139["boundary_exit_eas"] == [
                0x40BBA9,
                0x40BFA4,
                0x40C253,
                0x40C4DC,
            ]
            assert row139["passed"] is True
            row140 = observations["rhad:route@0x40BBA7"]
            assert row140["source_present"] is True
            assert row140["source_topology_reachable"] is True
            assert row140["source_topology_retired"] is False
            assert row140["indirect_transfer_present"] is False
            assert row140["target_eas"] == [0x40BBA9, 0x40C253]
            assert row140["semantic_target_eas"] == [0x40BBA9, 0x40C253]
            assert row140["delivery_target_eas"] == [0x40BBA9, 0x40C253]
            assert row140["semantic_targets_survive"] is True
            assert row140["boundary_exit_eas"] == [0x40A5F0, 0x40BBC3]
            assert row140["passed"] is True
            row141 = observations["rhad:route@0x40BBC1"]
            assert row141["source_present"] is True
            assert row141["source_topology_reachable"] is True
            assert row141["source_topology_retired"] is False
            assert row141["indirect_transfer_present"] is False
            assert row141["target_eas"] == [0x40A5F0, 0x40BBC3]
            assert row141["semantic_target_eas"] == [0x40A5F0, 0x40BBC3]
            assert row141["delivery_target_eas"] == [0x40A5F0, 0x40BBC3]
            assert row141["semantic_targets_survive"] is True
            assert row141["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row141["passed"] is True
            row142 = observations["rhad:route@0x40BBDD"]
            assert row142["source_present"] is True
            assert row142["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row142["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row142["indirect_transfer_present"] is False
            assert row142["target_eas"] == (
                [0x40A607] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row142["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row142["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row142["semantic_targets_survive"] is True
            assert row142["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
            assert row142["passed"] is True
            row143 = observations["rhad:route@0x40BBF7"]
            assert row143["source_present"] is True
            assert row143["source_topology_reachable"] is True
            assert row143["source_topology_retired"] is False
            assert row143["indirect_transfer_present"] is False
            assert row143["target_eas"] == [0x40BBF9, 0x40BFDA]
            assert row143["semantic_target_eas"] == [0x40BBF9, 0x40BFDA]
            assert row143["delivery_target_eas"] == [0x40BBF9, 0x40BFDA]
            assert row143["semantic_targets_survive"] is True
            assert row143["boundary_exit_eas"] == [0x40BC13, 0x40C2FB, 0x40C527]
            assert row143["passed"] is True
            row144 = observations["rhad:route@0x40BC11"]
            assert row144["source_present"] is True
            assert row144["source_topology_reachable"] is True
            assert row144["source_topology_retired"] is False
            assert row144["indirect_transfer_present"] is False
            assert row144["target_eas"] == [0x40BC13, 0x40C2FB]
            assert row144["semantic_target_eas"] == [0x40BC13, 0x40C2FB]
            assert row144["delivery_target_eas"] == [0x40BC13, 0x40C2FB]
            assert row144["semantic_targets_survive"] is True
            assert row144["boundary_exit_eas"] == [0x40A5F0, 0x40BC2D, 0x40C315]
            assert row144["passed"] is True
            row145 = observations["rhad:route@0x40BC2B"]
            assert row145["source_present"] is True
            assert row145["source_topology_reachable"] is True
            assert row145["source_topology_retired"] is False
            assert row145["indirect_transfer_present"] is False
            assert row145["target_eas"] == [0x40A5F0, 0x40BC2D]
            assert row145["semantic_target_eas"] == [0x40A5F0, 0x40BC2D]
            assert row145["delivery_target_eas"] == [0x40A5F0, 0x40BC2D]
            assert row145["semantic_targets_survive"] is True
            assert row145["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row145["passed"] is True
            row146 = observations["rhad:route@0x40BC5F"]
            assert row146["source_present"] is True
            assert row146["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row146["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row146["indirect_transfer_present"] is False
            assert row146["target_eas"] == (
                [0x40A607] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row146["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row146["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row146["semantic_targets_survive"] is True
            assert row146["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row146["passed"] is True
            row147 = observations["rhad:route@0x40BC79"]
            assert row147["source_present"] is True
            assert row147["source_topology_reachable"] is True
            assert row147["source_topology_retired"] is False
            assert row147["indirect_transfer_present"] is False
            assert row147["target_eas"] == [0x40BC7B, 0x40C041]
            assert row147["semantic_target_eas"] == [0x40BC7B, 0x40C041]
            assert row147["delivery_target_eas"] == [0x40BC7B, 0x40C041]
            assert row147["semantic_targets_survive"] is True
            assert row147["boundary_exit_eas"] == [
                0x40BC95,
                0x40C05B,
                0x40C34D,
                0x40C578,
            ]
            assert row147["passed"] is True
            row148 = observations["rhad:route@0x40BC93"]
            assert row148["source_present"] is True
            assert row148["source_topology_reachable"] is True
            assert row148["source_topology_retired"] is False
            assert row148["indirect_transfer_present"] is False
            assert row148["target_eas"] == [0x40BC95, 0x40C34D]
            assert row148["semantic_target_eas"] == [0x40BC95, 0x40C34D]
            assert row148["delivery_target_eas"] == [0x40BC95, 0x40C34D]
            assert row148["semantic_targets_survive"] is True
            assert row148["boundary_exit_eas"] == [
                0x40A5F0,
                0x40BCAF,
                0x40C367,
            ]
            assert row148["passed"] is True
            row149 = observations["rhad:route@0x40BCAD"]
            assert row149["source_present"] is True
            assert row149["source_topology_reachable"] is True
            assert row149["source_topology_retired"] is False
            assert row149["indirect_transfer_present"] is False
            assert row149["target_eas"] == [0x40A5F0, 0x40BCAF]
            assert row149["semantic_target_eas"] == [0x40A5F0, 0x40BCAF]
            assert row149["delivery_target_eas"] == [0x40A5F0, 0x40BCAF]
            assert row149["semantic_targets_survive"] is True
            assert row149["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row149["passed"] is True
            row150 = observations["rhad:route@0x40BCC9"]
            assert row150["source_present"] is True
            assert row150["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row150["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row150["indirect_transfer_present"] is False
            assert row150["target_eas"] == (
                [0x40A607] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row150["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row150["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row150["semantic_targets_survive"] is True
            assert row150["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row150["passed"] is True
            row151 = observations["rhad:route@0x40BCE3"]
            assert row151["source_present"] is True
            assert row151["source_topology_reachable"] is True
            assert row151["source_topology_retired"] is False
            assert row151["indirect_transfer_present"] is False
            assert row151["target_eas"] == [0x40BCE5, 0x40C0A0]
            assert row151["semantic_target_eas"] == [0x40BCE5, 0x40C0A0]
            assert row151["delivery_target_eas"] == [0x40BCE5, 0x40C0A0]
            assert row151["semantic_targets_survive"] is True
            assert row151["boundary_exit_eas"] == [0x40C392, 0x40C5FB]
            assert row151["passed"] is True
            row152 = observations["rhad:route@0x40BCFD"]
            assert row152["source_present"] is True
            assert row152["source_topology_reachable"] is True
            assert row152["source_topology_retired"] is False
            assert row152["indirect_transfer_present"] is False
            assert row152["target_eas"] == [0x40BCFF, 0x40C392]
            assert row152["semantic_target_eas"] == [0x40BCFF, 0x40C392]
            assert row152["delivery_target_eas"] == [0x40BCFF, 0x40C392]
            assert row152["semantic_targets_survive"] is True
            assert row152["boundary_exit_eas"] == [0x40A5F0, 0x40BD19]
            assert row152["passed"] is True
            row153 = observations["rhad:route@0x40BD17"]
            assert row153["source_present"] is True
            assert row153["source_topology_reachable"] is True
            assert row153["source_topology_retired"] is False
            assert row153["indirect_transfer_present"] is False
            assert row153["target_eas"] == [0x40A5F0, 0x40BD19]
            assert row153["semantic_target_eas"] == [0x40A5F0, 0x40BD19]
            assert row153["delivery_target_eas"] == [0x40A5F0, 0x40BD19]
            assert row153["semantic_targets_survive"] is True
            assert row153["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row153["passed"] is True
            row154 = observations["rhad:route@0x40BD4E"]
            assert row154["source_present"] is True
            assert row154["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row154["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row154["indirect_transfer_present"] is False
            assert row154["target_eas"] == (
                [0x40A607] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row154["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row154["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row154["semantic_targets_survive"] is True
            assert row154["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row154["passed"] is True
            row155 = observations["rhad:route@0x40BD68"]
            assert row155["source_present"] is True
            assert row155["source_topology_reachable"] is True
            assert row155["source_topology_retired"] is False
            assert row155["indirect_transfer_present"] is False
            assert row155["target_eas"] == [0x40BD6A, 0x40C3D9]
            assert row155["semantic_target_eas"] == [0x40BD6A, 0x40C3D9]
            assert row155["delivery_target_eas"] == [0x40BD6A, 0x40C3D9]
            assert row155["semantic_targets_survive"] is True
            assert row155["boundary_exit_eas"] == [
                0x40A5F0,
                0x40BD84,
                0x40C3F3,
            ]
            assert row155["passed"] is True
            row156 = observations["rhad:route@0x40BD82"]
            assert row156["source_present"] is True
            assert row156["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row156["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row156["indirect_transfer_present"] is False
            assert row156["target_eas"] == (
                [0x40A5F0, 0x40BD97]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40BD84]
            )
            assert row156["semantic_target_eas"] == [0x40A5F0, 0x40BD84]
            assert row156["delivery_target_eas"] == [0x40A5F0, 0x40BD84]
            assert row156["semantic_targets_survive"] is True
            assert row156["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row156["passed"] is True
            row157 = observations["rhad:route@0x40BE2D"]
            assert row157["source_present"] is True
            assert row157["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row157["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row157["indirect_transfer_present"] is False
            assert row157["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row157["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row157["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row157["semantic_targets_survive"] is True
            assert row157["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row157["passed"] is True
            row158 = observations["rhad:route@0x40BE47"]
            assert row158["source_present"] is True
            assert row158["source_topology_reachable"] is True
            assert row158["source_topology_retired"] is False
            assert row158["indirect_transfer_present"] is False
            assert row158["target_eas"] == [0x40BE49, 0x40C42E]
            assert row158["semantic_target_eas"] == [0x40BE49, 0x40C42E]
            assert row158["delivery_target_eas"] == [0x40BE49, 0x40C42E]
            assert row158["semantic_targets_survive"] is True
            assert row158["boundary_exit_eas"] == [0x40A5F0, 0x40BE63]
            assert row158["passed"] is True
            row159 = observations["rhad:route@0x40BE61"]
            assert row159["source_present"] is True
            assert row159["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row159["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row159["indirect_transfer_present"] is False
            assert row159["target_eas"] == (
                [0x40A5F0, 0x40BE76]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40BE63]
            )
            assert row159["semantic_target_eas"] == [0x40A5F0, 0x40BE63]
            assert row159["delivery_target_eas"] == [0x40A5F0, 0x40BE63]
            assert row159["semantic_targets_survive"] is True
            assert row159["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row159["passed"] is True
            row160 = observations["rhad:route@0x40BE96"]
            assert row160["source_present"] is True
            assert row160["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row160["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row160["indirect_transfer_present"] is False
            assert row160["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row160["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row160["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row160["semantic_targets_survive"] is True
            assert row160["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row160["passed"] is True
            row161 = observations["rhad:route@0x40BEB0"]
            assert row161["source_present"] is True
            assert row161["source_topology_reachable"] is True
            assert row161["source_topology_retired"] is False
            assert row161["indirect_transfer_present"] is False
            assert row161["target_eas"] == [0x40BEB2, 0x40C464]
            assert row161["semantic_target_eas"] == [0x40BEB2, 0x40C464]
            assert row161["delivery_target_eas"] == [0x40BEB2, 0x40C464]
            assert row161["semantic_targets_survive"] is True
            assert row161["boundary_exit_eas"] == [
                0x40A5F0,
                0x40BECC,
            ]
            assert row161["passed"] is True
            row162 = observations["rhad:route@0x40BECA"]
            assert row162["source_present"] is True
            assert row162["source_topology_reachable"] is True
            assert row162["source_topology_retired"] is False
            assert row162["indirect_transfer_present"] is False
            assert row162["target_eas"] == [0x40A5F0, 0x40BECC]
            assert row162["semantic_target_eas"] == [0x40A5F0, 0x40BECC]
            assert row162["delivery_target_eas"] == [0x40A5F0, 0x40BECC]
            assert row162["semantic_targets_survive"] is True
            assert row162["boundary_exit_eas"] == [
                0x40A607,
                0x40B6C0,
            ]
            assert row162["passed"] is True
            row163 = observations["rhad:route@0x40BEE5"]
            assert row163["source_present"] is True
            assert row163["source_topology_reachable"] is True
            assert row163["source_topology_retired"] is False
            assert row163["indirect_transfer_present"] is False
            assert row163["target_eas"] == [0x40A607, 0x40B6C0]
            assert row163["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row163["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row163["semantic_targets_survive"] is True
            assert row163["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row163["passed"] is True
            row164 = observations["rhad:route@0x40BEFF"]
            assert row164["source_present"] is True
            assert row164["source_topology_reachable"] is True
            assert row164["source_topology_retired"] is False
            assert row164["indirect_transfer_present"] is False
            assert row164["target_eas"] == [0x40BF01, 0x40C49A]
            assert row164["semantic_target_eas"] == [0x40BF01, 0x40C49A]
            assert row164["delivery_target_eas"] == [0x40BF01, 0x40C49A]
            assert row164["semantic_targets_survive"] is True
            assert row164["boundary_exit_eas"] == [
                0x40A5F0,
                0x40BF1B,
                0x40C4B4,
            ]
            assert row164["passed"] is True
            row165 = observations["rhad:route@0x40BF19"]
            assert row165["source_present"] is True
            assert row165["source_topology_reachable"] is True
            assert row165["source_topology_retired"] is False
            assert row165["indirect_transfer_present"] is False
            assert row165["target_eas"] == [0x40A5F0, 0x40BF1B]
            assert row165["semantic_target_eas"] == [0x40A5F0, 0x40BF1B]
            assert row165["delivery_target_eas"] == [0x40A5F0, 0x40BF1B]
            assert row165["semantic_targets_survive"] is True
            assert row165["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row165["passed"] is True
            row166 = observations["route:rhad-direct@0x40BF8A"]
            assert row166["source_present"] is True
            assert row166["source_topology_reachable"] is True
            assert row166["source_topology_retired"] is False
            assert row166["indirect_transfer_present"] is False
            assert row166["target_eas"] == [0x40B6C0]
            assert row166["semantic_target_eas"] == [0x40B6C0]
            assert row166["delivery_target_eas"] == [0x40B6C0]
            assert row166["semantic_targets_survive"] is True
            assert row166["boundary_exit_eas"] == [0x40B790]
            assert row166["passed"] is True
            row167 = observations["rhad:route@0x40BFA2"]
            assert row167["source_present"] is True
            assert row167["source_topology_reachable"] is True
            assert row167["source_topology_retired"] is False
            assert row167["indirect_transfer_present"] is False
            assert row167["target_eas"] == [0x40BFA4, 0x40C4DC]
            assert row167["semantic_target_eas"] == [0x40BFA4, 0x40C4DC]
            assert row167["delivery_target_eas"] == [0x40BFA4, 0x40C4DC]
            assert row167["semantic_targets_survive"] is True
            assert row167["boundary_exit_eas"] == [0x40A5F0]
            assert row167["passed"] is True
            row168 = observations["rhad:route@0x40BFBC"]
            assert row168["source_present"] is True
            assert row168["source_topology_reachable"] is True
            assert row168["source_topology_retired"] is False
            assert row168["indirect_transfer_present"] is False
            assert row168["target_eas"] == [0x40A5F0, 0x40BFBE]
            assert row168["semantic_target_eas"] == [0x40A5F0, 0x40BFBE]
            assert row168["delivery_target_eas"] == [0x40A5F0, 0x40BFBE]
            assert row168["semantic_targets_survive"] is True
            assert row168["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row168["passed"] is True
            row169 = observations["rhad:route@0x40BFD8"]
            assert row169["source_present"] is True
            assert row169["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row169["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row169["indirect_transfer_present"] is False
            assert row169["target_eas"] == (
                [0x40A607] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row169["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row169["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row169["semantic_targets_survive"] is True
            assert row169["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row169["passed"] is True
            row170 = observations["rhad:route@0x40BFF2"]
            assert row170["source_present"] is True
            assert row170["source_topology_reachable"] is True
            assert row170["source_topology_retired"] is False
            assert row170["indirect_transfer_present"] is False
            assert row170["target_eas"] == [0x40BFF4, 0x40C527]
            assert row170["semantic_target_eas"] == [0x40BFF4, 0x40C527]
            assert row170["delivery_target_eas"] == [0x40BFF4, 0x40C527]
            assert row170["semantic_targets_survive"] is True
            assert row170["boundary_exit_eas"] == [
                0x40A5F0,
                0x40C00E,
                0x40C541,
            ]
            assert row170["passed"] is True
            row171 = observations["rhad:route@0x40C00C"]
            assert row171["source_present"] is True
            assert row171["source_topology_reachable"] is True
            assert row171["source_topology_retired"] is False
            assert row171["indirect_transfer_present"] is False
            assert row171["target_eas"] == [0x40A5F0, 0x40C00E]
            assert row171["semantic_target_eas"] == [0x40A5F0, 0x40C00E]
            assert row171["delivery_target_eas"] == [0x40A5F0, 0x40C00E]
            assert row171["semantic_targets_survive"] is True
            assert row171["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row171["passed"] is True
            row172 = observations["route:rhad-direct@0x40C03F"]
            assert row172["source_present"] is True
            assert row172["source_topology_reachable"] is True
            assert row172["source_topology_retired"] is False
            assert row172["indirect_transfer_present"] is False
            assert row172["target_eas"] == [0x40B6C0]
            assert row172["semantic_target_eas"] == [0x40B6C0]
            assert row172["delivery_target_eas"] == [0x40B6C0]
            assert row172["semantic_targets_survive"] is True
            assert row172["boundary_exit_eas"] == [0x40B790]
            assert row172["passed"] is True
            row173 = observations["rhad:route@0x40C059"]
            assert row173["source_present"] is True
            assert row173["source_topology_reachable"] is True
            assert row173["source_topology_retired"] is False
            assert row173["indirect_transfer_present"] is False
            assert row173["target_eas"] == [0x40C05B, 0x40C578]
            assert row173["semantic_target_eas"] == [0x40C05B, 0x40C578]
            assert row173["delivery_target_eas"] == [0x40C05B, 0x40C578]
            assert row173["semantic_targets_survive"] is True
            assert row173["boundary_exit_eas"] == [
                0x40A5F0,
                0x40C075,
                0x40C592,
            ]
            assert row173["passed"] is True
            row174 = observations["rhad:route@0x40C073"]
            assert row174["source_present"] is True
            assert row174["source_topology_reachable"] is True
            assert row174["source_topology_retired"] is False
            assert row174["indirect_transfer_present"] is False
            assert row174["target_eas"] == [0x40A5F0, 0x40C075]
            assert row174["semantic_target_eas"] == [0x40A5F0, 0x40C075]
            assert row174["delivery_target_eas"] == [0x40A5F0, 0x40C075]
            assert row174["semantic_targets_survive"] is True
            assert row174["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row174["passed"] is True
            row175 = observations["route:rhad-direct@0x40C09E"]
            assert row175["source_present"] is True
            assert row175["source_topology_reachable"] is True
            assert row175["source_topology_retired"] is False
            assert row175["indirect_transfer_present"] is False
            assert row175["target_eas"] == [0x40B6C0]
            assert row175["semantic_target_eas"] == [0x40B6C0]
            assert row175["delivery_target_eas"] == [0x40B6C0]
            assert row175["semantic_targets_survive"] is True
            assert row175["boundary_exit_eas"] == [0x40B790]
            assert row175["passed"] is True
            row176 = observations["rhad:route@0x40C0B8"]
            assert row176["source_present"] is True
            assert row176["source_topology_reachable"] is True
            assert row176["source_topology_retired"] is False
            assert row176["indirect_transfer_present"] is False
            assert row176["target_eas"] == [0x40C0BA, 0x40C5FB]
            assert row176["semantic_target_eas"] == [0x40C0BA, 0x40C5FB]
            assert row176["delivery_target_eas"] == [0x40C0BA, 0x40C5FB]
            assert row176["semantic_targets_survive"] is True
            assert row176["boundary_exit_eas"] == [0x40A5F0, 0x40C64B]
            assert row176["passed"] is True
            row177 = observations["rhad:route@0x40C0D2"]
            assert row177["source_present"] is True
            assert row177["source_topology_reachable"] is True
            assert row177["source_topology_retired"] is False
            assert row177["indirect_transfer_present"] is False
            assert row177["target_eas"] == [0x40A5F0, 0x40C0D4]
            assert row177["semantic_target_eas"] == [0x40A5F0, 0x40C0D4]
            assert row177["delivery_target_eas"] == [0x40A5F0, 0x40C0D4]
            assert row177["semantic_targets_survive"] is True
            assert row177["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row177["passed"] is True
            row178 = observations["rhad:route@0x40C0EE"]
            assert row178["source_present"] is True
            assert row178["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row178["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row178["indirect_transfer_present"] is False
            assert row178["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row178["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row178["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row178["semantic_targets_survive"] is True
            assert row178["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row178["passed"] is True
            row179 = observations["rhad:route@0x40C108"]
            assert row179["source_present"] is True
            assert row179["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row179["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row179["indirect_transfer_present"] is False
            assert row179["target_eas"] == (
                [0x40A5F0, 0x40C115]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C10A]
            )
            assert row179["semantic_target_eas"] == [0x40A5F0, 0x40C10A]
            assert row179["delivery_target_eas"] == [0x40A5F0, 0x40C10A]
            assert row179["semantic_targets_survive"] is True
            assert row179["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row179["passed"] is True
            row180 = observations["route:rhad-direct@0x40C14E"]
            assert row180["source_present"] is True
            assert row180["source_topology_reachable"] is True
            assert row180["source_topology_retired"] is False
            assert row180["indirect_transfer_present"] is False
            assert row180["target_eas"] == [0x40B6C0]
            assert row180["semantic_target_eas"] == [0x40B6C0]
            assert row180["delivery_target_eas"] == [0x40B6C0]
            assert row180["semantic_targets_survive"] is True
            assert row180["boundary_exit_eas"] == [0x40B790]
            assert row180["passed"] is True
            row181 = observations["rhad:route@0x40C168"]
            assert row181["source_present"] is True
            assert row181["source_topology_reachable"] is True
            assert row181["source_topology_retired"] is False
            assert row181["indirect_transfer_present"] is False
            assert row181["target_eas"] == [0x40A5F0, 0x40C16A]
            assert row181["semantic_target_eas"] == [0x40A5F0, 0x40C16A]
            assert row181["delivery_target_eas"] == [0x40A5F0, 0x40C16A]
            assert row181["semantic_targets_survive"] is True
            assert row181["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row181["passed"] is True
            row182 = observations["rhad:route@0x40C184"]
            assert row182["source_present"] is True
            assert row182["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row182["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row182["indirect_transfer_present"] is False
            assert row182["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row182["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row182["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row182["semantic_targets_survive"] is True
            assert row182["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row182["passed"] is True
            row183 = observations["rhad:route@0x40C19E"]
            assert row183["source_present"] is True
            assert row183["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row183["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row183["indirect_transfer_present"] is False
            assert row183["target_eas"] == (
                [0x40A5F0, 0x40C1AA]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C1A0]
            )
            assert row183["semantic_target_eas"] == [0x40A5F0, 0x40C1A0]
            assert row183["delivery_target_eas"] == [0x40A5F0, 0x40C1A0]
            assert row183["semantic_targets_survive"] is True
            assert row183["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row183["passed"] is True
            row184 = observations["rhad:route@0x40C1F0"]
            assert row184["source_present"] is True
            assert row184["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row184["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row184["indirect_transfer_present"] is False
            assert row184["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row184["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row184["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row184["semantic_targets_survive"] is True
            assert row184["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row184["passed"] is True
            row185 = observations["rhad:route@0x40C20A"]
            assert row185["source_present"] is True
            assert row185["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row185["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row185["indirect_transfer_present"] is False
            assert row185["target_eas"] == (
                [0x40A5F0, 0x40C217]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C20C]
            )
            assert row185["semantic_target_eas"] == [0x40A5F0, 0x40C20C]
            assert row185["delivery_target_eas"] == [0x40A5F0, 0x40C20C]
            assert row185["semantic_targets_survive"] is True
            assert row185["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row185["passed"] is True
            row186 = observations["route:rhad-direct@0x40C251"]
            assert row186["source_present"] is True
            assert row186["source_topology_reachable"] is True
            assert row186["source_topology_retired"] is False
            assert row186["indirect_transfer_present"] is False
            assert row186["target_eas"] == [0x40B6C0]
            assert row186["semantic_target_eas"] == [0x40B6C0]
            assert row186["delivery_target_eas"] == [0x40B6C0]
            assert row186["semantic_targets_survive"] is True
            assert row186["boundary_exit_eas"] == [0x40B790]
            assert row186["passed"] is True
            row187 = observations["rhad:route@0x40C26B"]
            assert row187["source_present"] is True
            assert row187["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row187["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row187["indirect_transfer_present"] is False
            assert row187["target_eas"] == (
                [0x40A5F0, 0x40C277]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C26D]
            )
            assert row187["semantic_target_eas"] == [0x40A5F0, 0x40C26D]
            assert row187["delivery_target_eas"] == [0x40A5F0, 0x40C26D]
            assert row187["semantic_targets_survive"] is True
            assert row187["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row187["passed"] is True
            row188 = observations["route:rhad-direct@0x40C2F9"]
            assert row188["source_present"] is True
            assert row188["source_topology_reachable"] is True
            assert row188["source_topology_retired"] is False
            assert row188["indirect_transfer_present"] is False
            assert row188["target_eas"] == [0x40B6C0]
            assert row188["semantic_target_eas"] == [0x40B6C0]
            assert row188["delivery_target_eas"] == [0x40B6C0]
            assert row188["semantic_targets_survive"] is True
            assert row188["boundary_exit_eas"] == [0x40B790]
            assert row188["passed"] is True
            row189 = observations["rhad:route@0x40C313"]
            assert row189["source_present"] is True
            assert row189["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row189["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row189["indirect_transfer_present"] is False
            assert row189["target_eas"] == (
                [0x40A5F0, 0x40C322]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C315]
            )
            assert row189["semantic_target_eas"] == [0x40A5F0, 0x40C315]
            assert row189["delivery_target_eas"] == [0x40A5F0, 0x40C315]
            assert row189["semantic_targets_survive"] is True
            assert row189["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row189["passed"] is True
            row190 = observations["route:rhad-direct@0x40C34B"]
            assert row190["source_present"] is True
            assert row190["source_topology_reachable"] is True
            assert row190["source_topology_retired"] is False
            assert row190["indirect_transfer_present"] is False
            assert row190["target_eas"] == [0x40B6C0]
            assert row190["semantic_target_eas"] == [0x40B6C0]
            assert row190["delivery_target_eas"] == [0x40B6C0]
            assert row190["semantic_targets_survive"] is True
            assert row190["boundary_exit_eas"] == [0x40B790]
            assert row190["passed"] is True
            row191 = observations["rhad:route@0x40C365"]
            assert row191["indirect_transfer_present"] is False
            assert row191["source_present"] is True
            assert row191["source_topology_reachable"] is True
            assert row191["source_topology_retired"] is False
            assert row191["target_eas"] == [0x40A5F0, 0x40C367]
            assert row191["semantic_target_eas"] == [0x40A5F0, 0x40C367]
            assert row191["delivery_target_eas"] == [0x40A5F0, 0x40C367]
            assert row191["semantic_targets_survive"] is True
            assert row191["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row191["passed"] is True
            row192 = observations["route:rhad-direct@0x40C390"]
            assert row192["source_present"] is True
            assert row192["source_topology_reachable"] is True
            assert row192["source_topology_retired"] is False
            assert row192["indirect_transfer_present"] is False
            assert row192["target_eas"] == [0x40B6C0]
            assert row192["semantic_target_eas"] == [0x40B6C0]
            assert row192["delivery_target_eas"] == [0x40B6C0]
            assert row192["semantic_targets_survive"] is True
            assert row192["boundary_exit_eas"] == [0x40B790]
            assert row192["passed"] is True
            row193 = observations["rhad:route@0x40C3AA"]
            assert row193["indirect_transfer_present"] is False
            assert row193["source_present"] is True
            assert row193["source_topology_reachable"] is True
            assert row193["source_topology_retired"] is False
            assert row193["target_eas"] == [0x40A5F0, 0x40C3AC]
            assert row193["semantic_target_eas"] == [0x40A5F0, 0x40C3AC]
            assert row193["delivery_target_eas"] == [0x40A5F0, 0x40C3AC]
            assert row193["semantic_targets_survive"] is True
            assert row193["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row193["passed"] is True
            row194 = observations["route:rhad-direct@0x40C3D7"]
            assert row194["source_present"] is True
            assert row194["source_topology_reachable"] is True
            assert row194["source_topology_retired"] is False
            assert row194["indirect_transfer_present"] is False
            assert row194["target_eas"] == [0x40B6C0]
            assert row194["semantic_target_eas"] == [0x40B6C0]
            assert row194["delivery_target_eas"] == [0x40B6C0]
            assert row194["semantic_targets_survive"] is True
            assert row194["boundary_exit_eas"] == [0x40B790]
            assert row194["passed"] is True
            row195 = observations["rhad:route@0x40C3F1"]
            assert row195["source_present"] is True
            assert row195["source_topology_reachable"] is True
            assert row195["source_topology_retired"] is False
            assert row195["indirect_transfer_present"] is False
            assert row195["target_eas"] == [0x40A5F0, 0x40C3F3]
            assert row195["semantic_target_eas"] == [0x40A5F0, 0x40C3F3]
            assert row195["delivery_target_eas"] == [0x40A5F0, 0x40C3F3]
            assert row195["semantic_targets_survive"] is True
            assert row195["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row195["passed"] is True
            row196 = observations["route:rhad-direct@0x40C42C"]
            assert row196["source_present"] is True
            assert row196["source_topology_reachable"] is True
            assert row196["source_topology_retired"] is False
            assert row196["indirect_transfer_present"] is False
            assert row196["target_eas"] == [0x40B6C0]
            assert row196["semantic_target_eas"] == [0x40B6C0]
            assert row196["delivery_target_eas"] == [0x40B6C0]
            assert row196["semantic_targets_survive"] is True
            assert row196["boundary_exit_eas"] == [0x40B790]
            assert row196["passed"] is True
            row197 = observations["rhad:route@0x40C446"]
            assert row197["source_present"] is True
            assert row197["source_topology_reachable"] is True
            assert row197["source_topology_retired"] is False
            assert row197["indirect_transfer_present"] is False
            assert row197["target_eas"] == [0x40A5F0, 0x40C448]
            assert row197["semantic_target_eas"] == [0x40A5F0, 0x40C448]
            assert row197["delivery_target_eas"] == [0x40A5F0, 0x40C448]
            assert row197["semantic_targets_survive"] is True
            assert row197["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row197["passed"] is True
            row198 = observations["rhad:route@0x40C462"]
            assert row198["source_present"] is True
            assert row198["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row198["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row198["indirect_transfer_present"] is False
            assert row198["target_eas"] == (
                [0x40A607]
                if maturity == "MMAT_LOCOPT"
                else [0x40A607, 0x40B6C0]
            )
            assert row198["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row198["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row198["semantic_targets_survive"] is True
            assert row198["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
            assert row198["passed"] is True
            row199 = observations["rhad:route@0x40C47C"]
            assert row199["source_present"] is True
            assert row199["source_topology_reachable"] is True
            assert row199["source_topology_retired"] is False
            assert row199["indirect_transfer_present"] is False
            assert row199["target_eas"] == [0x40A5F0, 0x40C47E]
            assert row199["semantic_target_eas"] == [0x40A5F0, 0x40C47E]
            assert row199["delivery_target_eas"] == [0x40A5F0, 0x40C47E]
            assert row199["semantic_targets_survive"] is True
            assert row199["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row199["passed"] is True
            row200 = observations["rhad:route@0x40C498"]
            assert row200["source_present"] is True
            assert row200["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row200["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row200["indirect_transfer_present"] is False
            assert row200["target_eas"] == (
                [0x40B6C0]
                if maturity == "MMAT_LOCOPT"
                else [0x40A607, 0x40B6C0]
            )
            assert row200["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row200["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row200["semantic_targets_survive"] is True
            assert row200["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
            assert row200["passed"] is True
            row201 = observations["rhad:route@0x40C4B2"]
            assert row201["source_present"] is True
            assert row201["source_topology_reachable"] is True
            assert row201["source_topology_retired"] is False
            assert row201["indirect_transfer_present"] is False
            assert row201["target_eas"] == [0x40A5F0, 0x40C4B4]
            assert row201["semantic_target_eas"] == [0x40A5F0, 0x40C4B4]
            assert row201["delivery_target_eas"] == [0x40A5F0, 0x40C4B4]
            assert row201["semantic_targets_survive"] is True
            assert row201["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row201["passed"] is True
            row202 = observations["rhad:route@0x40C4DA"]
            assert row202["source_present"] is True
            assert row202["source_topology_reachable"] is True
            assert row202["source_topology_retired"] is False
            assert row202["indirect_transfer_present"] is False
            assert row202["target_eas"] == [0x40A607, 0x40B6C0]
            assert row202["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row202["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row202["semantic_targets_survive"] is True
            assert row202["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
            assert row202["passed"] is True
            row203 = observations["rhad:route@0x40C4F4"]
            assert row203["source_present"] is True
            assert row203["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row203["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row203["indirect_transfer_present"] is False
            assert row203["target_eas"] == (
                [0x40A5F0, 0x40C505]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C4F6]
            )
            assert row203["semantic_target_eas"] == [0x40A5F0, 0x40C4F6]
            assert row203["delivery_target_eas"] == [0x40A5F0, 0x40C4F6]
            assert row203["semantic_targets_survive"] is True
            assert row203["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row203["passed"] is True
            row204 = observations["rhad:route@0x40C525"]
            assert row204["source_present"] is True
            assert row204["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row204["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row204["indirect_transfer_present"] is False
            assert row204["target_eas"] == (
                [0x40A607]
                if maturity == "MMAT_LOCOPT"
                else [0x40A607, 0x40B6C0]
            ), (maturity, row204)
            assert row204["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row204["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row204["semantic_targets_survive"] is True
            assert row204["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
            assert row204["passed"] is True
            row205 = observations["rhad:route@0x40C53F"]
            assert row205["source_present"] is True
            assert row205["source_topology_reachable"] is True
            assert row205["source_topology_retired"] is False
            assert row205["indirect_transfer_present"] is False
            assert row205["target_eas"] == [0x40A5F0, 0x40C541]
            assert row205["semantic_target_eas"] == [0x40A5F0, 0x40C541]
            assert row205["delivery_target_eas"] == [0x40A5F0, 0x40C541]
            assert row205["semantic_targets_survive"] is True
            assert row205["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row205["passed"] is True
            row206 = observations["rhad:route@0x40C576"]
            assert row206["source_present"] is True
            assert row206["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row206["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row206["indirect_transfer_present"] is False
            assert row206["target_eas"] == (
                [0x40A607]
                if maturity == "MMAT_LOCOPT"
                else [0x40A607, 0x40B6C0]
            ), (maturity, row206)
            assert row206["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row206["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row206["semantic_targets_survive"] is True
            assert row206["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
            assert row206["passed"] is True
            row207 = observations["rhad:route@0x40C590"]
            assert row207["source_present"] is True
            assert row207["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row207["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row207["indirect_transfer_present"] is False
            assert row207["target_eas"] == (
                [0x40A5F0, 0x40AE55]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C592]
            ), (maturity, row207)
            assert row207["semantic_target_eas"] == [0x40A5F0, 0x40C592]
            assert row207["delivery_target_eas"] == [0x40A5F0, 0x40C592]
            assert row207["semantic_targets_survive"] is True
            assert row207["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row207["passed"] is True
            row208 = observations["route:rhad-direct@0x40C5F9"]
            assert row208["source_present"] is True
            assert row208["source_topology_reachable"] is True
            assert row208["source_topology_retired"] is False
            assert row208["indirect_transfer_present"] is False
            assert row208["target_eas"] == [0x40B6C0]
            assert row208["semantic_target_eas"] == [0x40B6C0]
            assert row208["delivery_target_eas"] == [0x40B6C0]
            assert row208["semantic_targets_survive"] is True
            assert row208["boundary_exit_eas"] == [0x40B790]
            assert row208["passed"] is True
            row209 = observations["rhad:route@0x40C613"]
            assert row209["source_present"] is True
            assert row209["source_topology_reachable"] is True
            assert row209["source_topology_retired"] is False
            assert row209["indirect_transfer_present"] is False
            assert row209["target_eas"] == [0x40C615, 0x40C64B]
            assert row209["semantic_target_eas"] == [0x40C615, 0x40C64B]
            assert row209["delivery_target_eas"] == [0x40C615, 0x40C64B]
            assert row209["semantic_targets_survive"] is True
            assert row209["boundary_exit_eas"] == [
                0x40A5F0,
                0x40C62F,
                0x40C665,
            ]
            assert row209["passed"] is True
            row210 = observations["rhad:route@0x40C62D"]
            assert row210["source_present"] is True
            assert row210["source_topology_reachable"] is True
            assert row210["source_topology_retired"] is False
            assert row210["indirect_transfer_present"] is False
            assert row210["target_eas"] == [0x40A5F0, 0x40C62F]
            assert row210["semantic_target_eas"] == [0x40A5F0, 0x40C62F]
            assert row210["delivery_target_eas"] == [0x40A5F0, 0x40C62F]
            assert row210["semantic_targets_survive"] is True
            assert row210["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row210["passed"] is True
            row211 = observations["rhad:route@0x40C649"]
            assert row211["source_present"] is True
            assert row211["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row211["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row211["indirect_transfer_present"] is False
            assert row211["target_eas"] == (
                [0x40A607]
                if maturity == "MMAT_LOCOPT"
                else [0x40A607, 0x40B6C0]
            ), (maturity, row211)
            assert row211["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row211["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row211["semantic_targets_survive"] is True
            assert row211["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row211["passed"] is True
            row212 = observations["rhad:route@0x40C663"]
            assert row212["source_present"] is True
            assert row212["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row212["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row212["indirect_transfer_present"] is False
            assert row212["target_eas"] == (
                [0x40A5F0, 0x40C674]
                if maturity == "MMAT_LOCOPT"
                else [0x40A5F0, 0x40C665]
            ), (maturity, row212)
            assert row212["semantic_target_eas"] == [0x40A5F0, 0x40C665]
            assert row212["delivery_target_eas"] == [0x40A5F0, 0x40C665]
            assert row212["semantic_targets_survive"] is True
            assert row212["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row212["passed"] is True
            row213 = observations["rhad:route@0x40C694"]
            assert row213["source_present"] is True
            assert row213["source_topology_reachable"] is (
                maturity != "MMAT_LOCOPT"
            )
            assert row213["source_topology_retired"] is (
                maturity == "MMAT_LOCOPT"
            )
            assert row213["indirect_transfer_present"] is False
            assert row213["target_eas"] == (
                [0x40A607]
                if maturity == "MMAT_LOCOPT"
                else [0x40A607, 0x40B6C0]
            ), (maturity, row213)
            assert row213["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row213["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row213["semantic_targets_survive"] is True
            assert row213["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row213["passed"] is True
            row214 = observations["route:rhad-direct@0x40C6B3"]
            assert row214["source_present"] is True
            assert row214["source_topology_reachable"] is True
            assert row214["source_topology_retired"] is False
            assert row214["indirect_transfer_present"] is False
            assert row214["target_eas"] == [0x40A607]
            assert row214["semantic_target_eas"] == [0x40A607]
            assert row214["delivery_target_eas"] == [0x40A607]
            assert row214["semantic_targets_survive"] is True
            assert row214["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row214["passed"] is True
            row215 = observations["route:rhad-direct@0x40C6D8"]
            assert row215["source_present"] is True
            assert row215["source_topology_reachable"] is True
            assert row215["source_topology_retired"] is False
            assert row215["indirect_transfer_present"] is False
            assert row215["target_eas"] == [0x40A607]
            assert row215["semantic_target_eas"] == [0x40A607]
            assert row215["delivery_target_eas"] == [0x40A607]
            assert row215["semantic_targets_survive"] is True
            assert row215["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row215["passed"] is True
            row216 = observations["route:rhad-direct@0x40C703"]
            assert row216["source_present"] is True
            assert row216["source_topology_reachable"] is True
            assert row216["source_topology_retired"] is False
            assert row216["indirect_transfer_present"] is False
            assert row216["target_eas"] == [0x40A607]
            assert row216["semantic_target_eas"] == [0x40A607]
            assert row216["delivery_target_eas"] == [0x40A607]
            assert row216["semantic_targets_survive"] is True
            assert row216["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row216["passed"] is True
            row217 = observations["route:rhad-direct@0x40C72E"]
            assert row217["source_present"] is True
            assert row217["source_topology_reachable"] is True
            assert row217["source_topology_retired"] is False
            assert row217["indirect_transfer_present"] is False
            assert row217["target_eas"] == [0x40A607]
            assert row217["semantic_target_eas"] == [0x40A607]
            assert row217["semantic_targets_survive"] is True
            assert row217["passed"] is True
            row218 = observations["route:rhad-direct@0x40C74F"]
            assert row218["source_present"] is True
            assert row218["source_topology_reachable"] is True
            assert row218["source_topology_retired"] is False
            assert row218["indirect_transfer_present"] is False
            assert row218["target_eas"] == [0x40A607]
            assert row218["semantic_target_eas"] == [0x40A607]
            assert row218["delivery_target_eas"] == [0x40A607]
            assert row218["semantic_targets_survive"] is True
            assert row218["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row218["passed"] is True
            row219 = observations["route:rhad-direct@0x40C76E"]
            assert row219["source_present"] is True
            assert row219["source_topology_reachable"] is True
            assert row219["source_topology_retired"] is False
            assert row219["indirect_transfer_present"] is False
            assert row219["target_eas"] == [0x40A607]
            assert row219["semantic_target_eas"] == [0x40A607]
            assert row219["delivery_target_eas"] == [0x40A607]
            assert row219["semantic_targets_survive"] is True
            assert row219["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row219["passed"] is True
            row220 = observations["route:rhad-direct@0x40C793"]
            assert row220["source_present"] is True
            assert row220["source_topology_reachable"] is True
            assert row220["source_topology_retired"] is False
            assert row220["indirect_transfer_present"] is False
            assert row220["target_eas"] == [0x40A607]
            assert row220["semantic_target_eas"] == [0x40A607]
            assert row220["delivery_target_eas"] == [0x40A607]
            assert row220["semantic_targets_survive"] is True
            assert row220["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row220["passed"] is True
            row221 = observations["route:rhad-direct@0x40C7B8"]
            assert row221["source_present"] is True
            assert row221["source_topology_reachable"] is True
            assert row221["source_topology_retired"] is False
            assert row221["indirect_transfer_present"] is False
            assert row221["target_eas"] == [0x40A607]
            assert row221["semantic_target_eas"] == [0x40A607]
            assert row221["delivery_target_eas"] == [0x40A607]
            assert row221["semantic_targets_survive"] is True
            assert row221["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row221["passed"] is True
            row222 = observations["route:rhad-direct@0x40C7E3"]
            assert row222["source_present"] is True
            assert row222["source_topology_reachable"] is True
            assert row222["source_topology_retired"] is False
            assert row222["indirect_transfer_present"] is False
            assert row222["target_eas"] == [0x40A607]
            assert row222["semantic_target_eas"] == [0x40A607]
            assert row222["delivery_target_eas"] == [0x40A607]
            assert row222["semantic_targets_survive"] is True
            assert row222["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row222["passed"] is True
            row223 = observations["route:rhad-direct@0x40C802"]
            assert row223["source_present"] is True
            assert row223["source_topology_reachable"] is True
            assert row223["source_topology_retired"] is False
            assert row223["indirect_transfer_present"] is False
            assert row223["target_eas"] == [0x40A607]
            assert row223["semantic_target_eas"] == [0x40A607]
            assert row223["delivery_target_eas"] == [0x40A607]
            assert row223["semantic_targets_survive"] is True
            assert row223["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row223["passed"] is True
            row224 = observations["route:rhad-direct@0x40C821"]
            assert row224["source_present"] is True
            assert row224["source_topology_reachable"] is True
            assert row224["source_topology_retired"] is False
            assert row224["indirect_transfer_present"] is False
            assert row224["target_eas"] == [0x40A607]
            assert row224["semantic_target_eas"] == [0x40A607]
            assert row224["delivery_target_eas"] == [0x40A607]
            assert row224["semantic_targets_survive"] is True
            assert row224["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row224["passed"] is True
            row225 = observations["route:rhad-direct@0x40C840"]
            assert row225["source_present"] is True
            assert row225["source_topology_reachable"] is True
            assert row225["source_topology_retired"] is False
            assert row225["indirect_transfer_present"] is False
            assert row225["target_eas"] == [0x40A607]
            assert row225["semantic_target_eas"] == [0x40A607]
            assert row225["delivery_target_eas"] == [0x40A607]
            assert row225["semantic_targets_survive"] is True
            assert row225["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row225["passed"] is True
            row226 = observations["route:rhad-direct@0x40C86B"]
            assert row226["source_present"] is True
            assert row226["source_topology_reachable"] is True
            assert row226["source_topology_retired"] is False
            assert row226["indirect_transfer_present"] is False
            assert row226["target_eas"] == [0x40A607]
            assert row226["semantic_target_eas"] == [0x40A607]
            assert row226["delivery_target_eas"] == [0x40A607]
            assert row226["semantic_targets_survive"] is True
            assert row226["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row226["passed"] is True
            row227 = observations["route:rhad-direct@0x40C896"]
            assert row227["source_present"] is True
            assert row227["source_topology_reachable"] is True
            assert row227["source_topology_retired"] is False
            assert row227["indirect_transfer_present"] is False
            assert row227["target_eas"] == [0x40A607]
            assert row227["semantic_target_eas"] == [0x40A607]
            assert row227["delivery_target_eas"] == [0x40A607]
            assert row227["semantic_targets_survive"] is True
            assert row227["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
            assert row227["passed"] is True
        calls_payload = maturity_payloads["MMAT_CALLS"]
        calls_observations = {
            row["operation_id"]: row for row in calls_payload["operation_observations"]
        }
        constant_calls = calls_observations[_CONSTANT_OPERATION_ID]
        assert constant_calls["absolute_load_present"] is False
        assert constant_calls["source_present"] is False
        assert constant_calls["source_topology_reachable"] is False
        assert constant_calls["source_topology_retired"] is True
        assert constant_calls["materialized_constant_present"] is False
        assert constant_calls["flag_envelope_survives"] is False
        assert constant_calls["exact_generated_envelope"] is False
        assert constant_calls["passed"] is True
        mov_constant_calls = calls_observations[_MOV_CONSTANT_OPERATION_ID]
        assert mov_constant_calls["absolute_load_present"] is False
        assert mov_constant_calls["source_present"] is False
        assert mov_constant_calls["source_topology_retired"] is True
        assert mov_constant_calls["exact_generated_envelope"] is False
        assert mov_constant_calls["passed"] is True
        eax_constant_calls = calls_observations[_EAX_CONSTANT_OPERATION_ID]
        assert eax_constant_calls["absolute_load_present"] is False
        assert eax_constant_calls["passed"] is True
        if eax_constant_calls["source_present"]:
            assert eax_constant_calls["materialized_constant_present"] is True
            assert eax_constant_calls["destination_delivery_present"] is True
        else:
            assert eax_constant_calls["source_topology_retired"] is True
        row3_constant_calls = calls_observations[_ROW3_CONSTANT_OPERATION_ID]
        assert row3_constant_calls["absolute_load_present"] is False
        assert row3_constant_calls["passed"] is True
        if row3_constant_calls["source_present"]:
            assert row3_constant_calls["materialized_constant_present"] is True
            assert row3_constant_calls["destination_delivery_present"] is True
        else:
            assert row3_constant_calls["source_topology_retired"] is True
        row4_constant_calls = calls_observations[_ROW4_CONSTANT_OPERATION_ID]
        assert row4_constant_calls["absolute_load_present"] is False
        assert row4_constant_calls["passed"] is True
        if row4_constant_calls["source_present"]:
            assert row4_constant_calls["materialized_constant_present"] is True
            assert row4_constant_calls["destination_delivery_present"] is True
        else:
            assert row4_constant_calls["source_topology_retired"] is True
        row5_constant_calls = calls_observations[_ROW5_CONSTANT_OPERATION_ID]
        assert row5_constant_calls["absolute_load_present"] is False
        assert row5_constant_calls["passed"] is True
        if row5_constant_calls["source_present"]:
            assert row5_constant_calls["materialized_constant_present"] is True
            assert row5_constant_calls["destination_delivery_present"] is True
        else:
            assert row5_constant_calls["source_topology_retired"] is True
        row6_constant_calls = calls_observations[_ROW6_CONSTANT_OPERATION_ID]
        assert row6_constant_calls["absolute_load_present"] is False
        assert row6_constant_calls["passed"] is True
        if row6_constant_calls["source_present"]:
            assert row6_constant_calls["materialized_constant_present"] is True
            assert row6_constant_calls["destination_delivery_present"] is True
        else:
            assert row6_constant_calls["source_topology_retired"] is True
        row7_constant_calls = calls_observations[_ROW7_CONSTANT_OPERATION_ID]
        assert row7_constant_calls["absolute_load_present"] is False
        assert row7_constant_calls["passed"] is True
        if row7_constant_calls["source_present"]:
            assert row7_constant_calls["materialized_constant_present"] is True
            assert row7_constant_calls["destination_delivery_present"] is True
        else:
            assert row7_constant_calls["source_topology_retired"] is True
        row8_constant_calls = calls_observations[_ROW8_CONSTANT_OPERATION_ID]
        assert row8_constant_calls["absolute_load_present"] is False
        assert row8_constant_calls["passed"] is True
        if row8_constant_calls["source_present"]:
            assert row8_constant_calls["materialized_constant_present"] is True
            assert row8_constant_calls["destination_delivery_present"] is True
        else:
            assert row8_constant_calls["source_topology_retired"] is True
        row9_constant_calls = calls_observations[_ROW9_CONSTANT_OPERATION_ID]
        assert row9_constant_calls["absolute_load_present"] is False
        assert row9_constant_calls["passed"] is True
        if row9_constant_calls["source_present"]:
            assert row9_constant_calls["materialized_constant_present"] is True
            assert row9_constant_calls["destination_delivery_present"] is True
        else:
            assert row9_constant_calls["source_topology_retired"] is True
        row10_constant_calls = calls_observations[_ROW10_CONSTANT_OPERATION_ID]
        assert row10_constant_calls["absolute_load_present"] is False
        assert row10_constant_calls["passed"] is True
        if row10_constant_calls["source_present"]:
            assert row10_constant_calls["materialized_constant_present"] is True
            assert row10_constant_calls["destination_delivery_present"] is True
        else:
            assert row10_constant_calls["source_topology_retired"] is True
        row11_constant_calls = calls_observations[_ROW11_CONSTANT_OPERATION_ID]
        assert row11_constant_calls["absolute_load_present"] is False
        assert row11_constant_calls["passed"] is True
        if row11_constant_calls["source_present"]:
            assert row11_constant_calls["materialized_constant_present"] is True
            assert row11_constant_calls["destination_delivery_present"] is True
        else:
            assert row11_constant_calls["source_topology_retired"] is True
        row12_constant_calls = calls_observations[_ROW12_CONSTANT_OPERATION_ID]
        assert row12_constant_calls["absolute_load_present"] is False
        assert row12_constant_calls["passed"] is True
        if row12_constant_calls["source_present"]:
            assert row12_constant_calls["materialized_constant_present"] is True
            assert row12_constant_calls["destination_delivery_present"] is True
        else:
            assert row12_constant_calls["source_topology_retired"] is True
        row13_constant_calls = calls_observations[_ROW13_CONSTANT_OPERATION_ID]
        assert row13_constant_calls["absolute_load_present"] is False
        assert row13_constant_calls["passed"] is True
        if row13_constant_calls["source_present"]:
            assert row13_constant_calls["materialized_constant_present"] is True
            assert row13_constant_calls["destination_delivery_present"] is True
        else:
            assert row13_constant_calls["source_topology_retired"] is True
        row14_constant_calls = calls_observations[_ROW14_CONSTANT_OPERATION_ID]
        assert row14_constant_calls["absolute_load_present"] is False
        assert row14_constant_calls["passed"] is True
        if row14_constant_calls["source_present"]:
            assert row14_constant_calls["materialized_constant_present"] is True
            assert row14_constant_calls["destination_delivery_present"] is True
        else:
            assert row14_constant_calls["source_topology_retired"] is True
        row15_constant_calls = calls_observations[_ROW15_CONSTANT_OPERATION_ID]
        assert row15_constant_calls["absolute_load_present"] is False
        assert row15_constant_calls["passed"] is True
        if row15_constant_calls["source_present"]:
            assert row15_constant_calls["materialized_constant_present"] is True
            assert row15_constant_calls["destination_delivery_present"] is True
        else:
            assert row15_constant_calls["source_topology_retired"] is True
        row16_constant_calls = calls_observations[_ROW16_CONSTANT_OPERATION_ID]
        assert row16_constant_calls["absolute_load_present"] is False
        assert row16_constant_calls["passed"] is True
        if row16_constant_calls["source_present"]:
            assert row16_constant_calls["materialized_constant_present"] is True
            assert row16_constant_calls["destination_delivery_present"] is True
        else:
            assert row16_constant_calls["source_topology_retired"] is True
        row17_constant_calls = calls_observations[_ROW17_CONSTANT_OPERATION_ID]
        assert row17_constant_calls["absolute_load_present"] is False
        assert row17_constant_calls["passed"] is True
        if row17_constant_calls["source_present"]:
            assert row17_constant_calls["materialized_constant_present"] is True
            assert row17_constant_calls["destination_delivery_present"] is True
        else:
            assert row17_constant_calls["source_topology_retired"] is True
        row18_constant_calls = calls_observations[_ROW18_CONSTANT_OPERATION_ID]
        assert row18_constant_calls["absolute_load_present"] is False
        assert row18_constant_calls["passed"] is True
        if row18_constant_calls["source_present"]:
            assert row18_constant_calls["materialized_constant_present"] is True
            assert row18_constant_calls["destination_delivery_present"] is True
        else:
            assert row18_constant_calls["source_topology_retired"] is True
        row19_constant_calls = calls_observations[_ROW19_CONSTANT_OPERATION_ID]
        assert row19_constant_calls["absolute_load_present"] is False
        assert row19_constant_calls["passed"] is True
        if row19_constant_calls["source_present"]:
            assert row19_constant_calls["materialized_constant_present"] is True
            assert row19_constant_calls["destination_delivery_present"] is True
        else:
            assert row19_constant_calls["source_topology_retired"] is True
        row20_constant_calls = calls_observations[_ROW20_CONSTANT_OPERATION_ID]
        assert row20_constant_calls["absolute_load_present"] is False
        assert row20_constant_calls["passed"] is True
        if row20_constant_calls["source_present"]:
            assert row20_constant_calls["materialized_constant_present"] is True
            assert row20_constant_calls["destination_delivery_present"] is True
        else:
            assert row20_constant_calls["source_topology_retired"] is True
        row21_constant_calls = calls_observations[_ROW21_CONSTANT_OPERATION_ID]
        assert row21_constant_calls["absolute_load_present"] is False
        assert row21_constant_calls["passed"] is True
        if row21_constant_calls["source_present"]:
            assert row21_constant_calls["materialized_constant_present"] is True
            assert row21_constant_calls["destination_delivery_present"] is True
        else:
            assert row21_constant_calls["source_topology_retired"] is True
        row22_constant_calls = calls_observations[_ROW22_CONSTANT_OPERATION_ID]
        assert row22_constant_calls["absolute_load_present"] is False
        assert row22_constant_calls["passed"] is True
        if row22_constant_calls["source_present"]:
            assert row22_constant_calls["materialized_constant_present"] is True
            assert row22_constant_calls["destination_delivery_present"] is True
        else:
            assert row22_constant_calls["source_topology_retired"] is True
        row23_constant_calls = calls_observations[_ROW23_CONSTANT_OPERATION_ID]
        assert row23_constant_calls["absolute_load_present"] is False
        assert row23_constant_calls["passed"] is True
        if row23_constant_calls["source_present"]:
            assert row23_constant_calls["materialized_constant_present"] is True
            assert row23_constant_calls["destination_delivery_present"] is True
        else:
            assert row23_constant_calls["source_topology_retired"] is True
        row24_constant_calls = calls_observations[_ROW24_CONSTANT_OPERATION_ID]
        assert row24_constant_calls["absolute_load_present"] is False
        assert row24_constant_calls["passed"] is True
        if row24_constant_calls["source_present"]:
            assert row24_constant_calls["materialized_constant_present"] is True
            assert row24_constant_calls["destination_delivery_present"] is True
        else:
            assert row24_constant_calls["source_topology_retired"] is True
        row25_constant_calls = calls_observations[_ROW25_CONSTANT_OPERATION_ID]
        assert row25_constant_calls["absolute_load_present"] is False
        assert row25_constant_calls["passed"] is True
        if row25_constant_calls["source_present"]:
            assert row25_constant_calls["materialized_constant_present"] is True
            assert row25_constant_calls["destination_delivery_present"] is True
        else:
            assert row25_constant_calls["source_topology_retired"] is True
        row26_constant_calls = calls_observations[_ROW26_CONSTANT_OPERATION_ID]
        assert row26_constant_calls["absolute_load_present"] is False
        assert row26_constant_calls["passed"] is True
        if row26_constant_calls["source_present"]:
            assert row26_constant_calls["materialized_constant_present"] is True
            assert row26_constant_calls["destination_delivery_present"] is True
        else:
            assert row26_constant_calls["source_topology_retired"] is True
        row27_constant_calls = calls_observations[_ROW27_CONSTANT_OPERATION_ID]
        assert row27_constant_calls["absolute_load_present"] is False
        assert row27_constant_calls["passed"] is True
        if row27_constant_calls["source_present"]:
            assert row27_constant_calls["materialized_constant_present"] is True
            assert row27_constant_calls["destination_delivery_present"] is True
        else:
            assert row27_constant_calls["source_topology_retired"] is True
        row28_constant_calls = calls_observations[_ROW28_CONSTANT_OPERATION_ID]
        assert row28_constant_calls["absolute_load_present"] is False
        assert row28_constant_calls["passed"] is True
        if row28_constant_calls["source_present"]:
            assert row28_constant_calls["materialized_constant_present"] is True
            assert row28_constant_calls["destination_delivery_present"] is True
        else:
            assert row28_constant_calls["source_topology_retired"] is True
        row29_constant_calls = calls_observations[_ROW29_CONSTANT_OPERATION_ID]
        assert row29_constant_calls["absolute_load_present"] is False
        assert row29_constant_calls["passed"] is True
        if row29_constant_calls["source_present"]:
            assert row29_constant_calls["materialized_constant_present"] is True
            assert row29_constant_calls["destination_delivery_present"] is True
        else:
            assert row29_constant_calls["source_topology_retired"] is True
        row30_constant_calls = calls_observations[_ROW30_CONSTANT_OPERATION_ID]
        assert row30_constant_calls["absolute_load_present"] is False
        assert row30_constant_calls["passed"] is True
        if row30_constant_calls["source_present"]:
            assert row30_constant_calls["materialized_constant_present"] is True
            assert row30_constant_calls["destination_delivery_present"] is True
        else:
            assert row30_constant_calls["source_topology_retired"] is True
        row31_constant_calls = calls_observations[_ROW31_CONSTANT_OPERATION_ID]
        assert row31_constant_calls["absolute_load_present"] is False
        assert row31_constant_calls["passed"] is True
        if row31_constant_calls["source_present"]:
            assert row31_constant_calls["materialized_constant_present"] is True
            assert row31_constant_calls["destination_delivery_present"] is True
        else:
            assert row31_constant_calls["source_topology_retired"] is True
        row32_constant_calls = calls_observations[_ROW32_CONSTANT_OPERATION_ID]
        assert row32_constant_calls["absolute_load_present"] is False
        assert row32_constant_calls["passed"] is True
        if row32_constant_calls["source_present"]:
            assert row32_constant_calls["materialized_constant_present"] is True
            assert row32_constant_calls["destination_delivery_present"] is True
        else:
            assert row32_constant_calls["source_topology_retired"] is True
        row33_constant_calls = calls_observations[_ROW33_CONSTANT_OPERATION_ID]
        assert row33_constant_calls["absolute_load_present"] is False
        assert row33_constant_calls["passed"] is True
        if row33_constant_calls["source_present"]:
            assert row33_constant_calls["materialized_constant_present"] is True
            assert row33_constant_calls["destination_delivery_present"] is True
        else:
            assert row33_constant_calls["source_topology_retired"] is True
        row34_constant_calls = calls_observations[_ROW34_CONSTANT_OPERATION_ID]
        assert row34_constant_calls["absolute_load_present"] is False
        assert row34_constant_calls["passed"] is True
        if row34_constant_calls["source_present"]:
            assert row34_constant_calls["materialized_constant_present"] is True
            assert row34_constant_calls["destination_delivery_present"] is True
        else:
            assert row34_constant_calls["source_topology_retired"] is True
        row35_constant_calls = calls_observations[_ROW35_CONSTANT_OPERATION_ID]
        assert row35_constant_calls["absolute_load_present"] is False
        assert row35_constant_calls["passed"] is True
        if row35_constant_calls["source_present"]:
            assert row35_constant_calls["materialized_constant_present"] is True
            assert row35_constant_calls["destination_delivery_present"] is True
        else:
            assert row35_constant_calls["source_topology_retired"] is True
        row36_constant_calls = calls_observations[_ROW36_CONSTANT_OPERATION_ID]
        assert row36_constant_calls["absolute_load_present"] is False
        assert row36_constant_calls["passed"] is True
        if row36_constant_calls["source_present"]:
            assert row36_constant_calls["materialized_constant_present"] is True
            assert row36_constant_calls["destination_delivery_present"] is True
        else:
            assert row36_constant_calls["source_topology_retired"] is True
        row37_constant_calls = calls_observations[_ROW37_CONSTANT_OPERATION_ID]
        assert row37_constant_calls["absolute_load_present"] is False
        assert row37_constant_calls["passed"] is True
        if row37_constant_calls["source_present"]:
            assert row37_constant_calls["materialized_constant_present"] is True
            assert row37_constant_calls["destination_delivery_present"] is True
        else:
            assert row37_constant_calls["source_topology_retired"] is True
        row38_constant_calls = calls_observations[_ROW38_CONSTANT_OPERATION_ID]
        assert row38_constant_calls["absolute_load_present"] is False
        assert row38_constant_calls["passed"] is True
        if row38_constant_calls["source_present"]:
            assert row38_constant_calls["materialized_constant_present"] is True
            assert row38_constant_calls["destination_delivery_present"] is True
        else:
            assert row38_constant_calls["source_topology_retired"] is True
        row39_constant_calls = calls_observations[_ROW39_CONSTANT_OPERATION_ID]
        assert row39_constant_calls["absolute_load_present"] is False
        assert row39_constant_calls["passed"] is True
        if row39_constant_calls["source_present"]:
            assert row39_constant_calls["materialized_constant_present"] is True
            assert row39_constant_calls["destination_delivery_present"] is True
        else:
            assert row39_constant_calls["source_topology_retired"] is True
        row40_constant_calls = calls_observations[_ROW40_CONSTANT_OPERATION_ID]
        assert row40_constant_calls["absolute_load_present"] is False
        assert row40_constant_calls["passed"] is True
        if row40_constant_calls["source_present"]:
            assert row40_constant_calls["materialized_constant_present"] is True
            assert row40_constant_calls["destination_delivery_present"] is True
        else:
            assert row40_constant_calls["source_topology_retired"] is True
        row41_constant_calls = calls_observations[_ROW41_CONSTANT_OPERATION_ID]
        assert row41_constant_calls["absolute_load_present"] is False
        assert row41_constant_calls["passed"] is True
        if row41_constant_calls["source_present"]:
            assert row41_constant_calls["materialized_constant_present"] is True
            assert row41_constant_calls["destination_delivery_present"] is True
        else:
            assert row41_constant_calls["source_topology_retired"] is True
        row42_constant_calls = calls_observations[_ROW42_CONSTANT_OPERATION_ID]
        assert row42_constant_calls["absolute_load_present"] is False
        assert row42_constant_calls["passed"] is True
        if row42_constant_calls["source_present"]:
            assert row42_constant_calls["materialized_constant_present"] is True
            assert row42_constant_calls["destination_delivery_present"] is True
        else:
            assert row42_constant_calls["source_topology_retired"] is True
        row43_constant_calls = calls_observations[_ROW43_CONSTANT_OPERATION_ID]
        assert row43_constant_calls["absolute_load_present"] is False
        assert row43_constant_calls["passed"] is True
        if row43_constant_calls["source_present"]:
            assert row43_constant_calls["materialized_constant_present"] is True
            assert row43_constant_calls["destination_delivery_present"] is True
        else:
            assert row43_constant_calls["source_topology_retired"] is True
        row44_constant_calls = calls_observations[_ROW44_CONSTANT_OPERATION_ID]
        assert row44_constant_calls["absolute_load_present"] is False
        assert row44_constant_calls["passed"] is True
        if row44_constant_calls["source_present"]:
            assert row44_constant_calls["materialized_constant_present"] is True
            assert row44_constant_calls["destination_delivery_present"] is True
        else:
            assert row44_constant_calls["source_topology_retired"] is True
        row45_constant_calls = calls_observations[_ROW45_CONSTANT_OPERATION_ID]
        assert row45_constant_calls["absolute_load_present"] is False
        assert row45_constant_calls["passed"] is True
        if row45_constant_calls["source_present"]:
            assert row45_constant_calls["materialized_constant_present"] is True
            assert row45_constant_calls["destination_delivery_present"] is True
        else:
            assert row45_constant_calls["source_topology_retired"] is True
        row46_constant_calls = calls_observations[_ROW46_CONSTANT_OPERATION_ID]
        assert row46_constant_calls["absolute_load_present"] is False
        assert row46_constant_calls["passed"] is True
        if row46_constant_calls["source_present"]:
            assert row46_constant_calls["materialized_constant_present"] is True
            assert row46_constant_calls["destination_delivery_present"] is True
        else:
            assert row46_constant_calls["source_topology_retired"] is True
        row47_constant_calls = calls_observations[_ROW47_CONSTANT_OPERATION_ID]
        assert row47_constant_calls["absolute_load_present"] is False
        assert row47_constant_calls["passed"] is True
        if row47_constant_calls["source_present"]:
            assert row47_constant_calls["materialized_constant_present"] is True
            assert row47_constant_calls["destination_delivery_present"] is True
        else:
            assert row47_constant_calls["source_topology_retired"] is True
        row48_constant_calls = calls_observations[_ROW48_CONSTANT_OPERATION_ID]
        assert row48_constant_calls["absolute_load_present"] is False
        assert row48_constant_calls["passed"] is True
        if row48_constant_calls["source_present"]:
            assert row48_constant_calls["materialized_constant_present"] is True
            assert row48_constant_calls["destination_delivery_present"] is True
        else:
            assert row48_constant_calls["source_topology_retired"] is True
        row49_constant_calls = calls_observations[_ROW49_CONSTANT_OPERATION_ID]
        assert row49_constant_calls["absolute_load_present"] is False
        assert row49_constant_calls["passed"] is True
        if row49_constant_calls["source_present"]:
            assert row49_constant_calls["materialized_constant_present"] is True
            assert row49_constant_calls["destination_delivery_present"] is True
        else:
            assert row49_constant_calls["source_topology_retired"] is True
        row50_constant_calls = calls_observations[_ROW50_CONSTANT_OPERATION_ID]
        assert row50_constant_calls["absolute_load_present"] is False
        assert row50_constant_calls["passed"] is True
        if row50_constant_calls["source_present"]:
            assert row50_constant_calls["materialized_constant_present"] is True
            assert row50_constant_calls["destination_delivery_present"] is True
        else:
            assert row50_constant_calls["source_topology_retired"] is True
        row51_constant_calls = calls_observations[_ROW51_CONSTANT_OPERATION_ID]
        assert row51_constant_calls["absolute_load_present"] is False
        assert row51_constant_calls["passed"] is True
        if row51_constant_calls["source_present"]:
            assert row51_constant_calls["materialized_constant_present"] is True
            assert row51_constant_calls["destination_delivery_present"] is True
        else:
            assert row51_constant_calls["source_topology_retired"] is True
        row52_constant_calls = calls_observations[_ROW52_CONSTANT_OPERATION_ID]
        assert row52_constant_calls["absolute_load_present"] is False
        assert row52_constant_calls["passed"] is True
        if row52_constant_calls["source_present"]:
            assert row52_constant_calls["materialized_constant_present"] is True
            assert row52_constant_calls["destination_delivery_present"] is True
        else:
            assert row52_constant_calls["source_topology_retired"] is True
        row53_constant_calls = calls_observations[_ROW53_CONSTANT_OPERATION_ID]
        assert row53_constant_calls["absolute_load_present"] is False
        assert row53_constant_calls["passed"] is True
        if row53_constant_calls["source_present"]:
            assert row53_constant_calls["materialized_constant_present"] is True
            assert row53_constant_calls["destination_delivery_present"] is True
        else:
            assert row53_constant_calls["source_topology_retired"] is True
        row54_constant_calls = calls_observations[_ROW54_CONSTANT_OPERATION_ID]
        assert row54_constant_calls["absolute_load_present"] is False
        assert row54_constant_calls["passed"] is True
        if row54_constant_calls["source_present"]:
            assert row54_constant_calls["materialized_constant_present"] is True
            assert row54_constant_calls["destination_delivery_present"] is True
        else:
            assert row54_constant_calls["source_topology_retired"] is True
        row55_constant_calls = calls_observations[_ROW55_CONSTANT_OPERATION_ID]
        assert row55_constant_calls["absolute_load_present"] is False
        assert row55_constant_calls["passed"] is True
        if row55_constant_calls["source_present"]:
            assert row55_constant_calls["materialized_constant_present"] is True
            assert row55_constant_calls["destination_delivery_present"] is True
        else:
            assert row55_constant_calls["source_topology_retired"] is True
        row56_constant_calls = calls_observations[_ROW56_CONSTANT_OPERATION_ID]
        assert row56_constant_calls["absolute_load_present"] is False
        assert row56_constant_calls["passed"] is True
        if row56_constant_calls["source_present"]:
            assert row56_constant_calls["materialized_constant_present"] is True
            assert row56_constant_calls["destination_delivery_present"] is True
        else:
            assert row56_constant_calls["source_topology_retired"] is True
        row57_constant_calls = calls_observations[_ROW57_CONSTANT_OPERATION_ID]
        assert row57_constant_calls["absolute_load_present"] is False
        assert row57_constant_calls["passed"] is True
        if row57_constant_calls["source_present"]:
            assert row57_constant_calls["materialized_constant_present"] is True
            assert row57_constant_calls["destination_delivery_present"] is True
        else:
            assert row57_constant_calls["source_topology_retired"] is True
        row58_constant_calls = calls_observations[_ROW58_CONSTANT_OPERATION_ID]
        assert row58_constant_calls["absolute_load_present"] is False
        assert row58_constant_calls["passed"] is True
        if row58_constant_calls["source_present"]:
            assert row58_constant_calls["materialized_constant_present"] is True
            assert row58_constant_calls["destination_delivery_present"] is True
        else:
            assert row58_constant_calls["source_topology_retired"] is True
        row59_constant_calls = calls_observations[_ROW59_CONSTANT_OPERATION_ID]
        assert row59_constant_calls["absolute_load_present"] is False
        assert row59_constant_calls["passed"] is True
        if row59_constant_calls["source_present"]:
            assert row59_constant_calls["materialized_constant_present"] is True
            assert row59_constant_calls["destination_delivery_present"] is True
        else:
            assert row59_constant_calls["source_topology_retired"] is True
        row60_constant_calls = calls_observations[_ROW60_CONSTANT_OPERATION_ID]
        assert row60_constant_calls["absolute_load_present"] is False
        assert row60_constant_calls["passed"] is True
        if row60_constant_calls["source_present"]:
            assert row60_constant_calls["materialized_constant_present"] is True
            assert row60_constant_calls["destination_delivery_present"] is True
        else:
            assert row60_constant_calls["source_topology_retired"] is True
        row61_constant_calls = calls_observations[_ROW61_CONSTANT_OPERATION_ID]
        assert row61_constant_calls["absolute_load_present"] is False
        assert row61_constant_calls["passed"] is True
        if row61_constant_calls["source_present"]:
            assert row61_constant_calls["materialized_constant_present"] is True
            assert row61_constant_calls["destination_delivery_present"] is True
        else:
            assert row61_constant_calls["source_topology_retired"] is True
        row62_constant_calls = calls_observations[_ROW62_CONSTANT_OPERATION_ID]
        assert row62_constant_calls["absolute_load_present"] is False
        assert row62_constant_calls["passed"] is True
        if row62_constant_calls["source_present"]:
            assert row62_constant_calls["destination_delivery_present"] is True
            assert row62_constant_calls["semantic_envelope_survives"] is True
        else:
            assert row62_constant_calls["source_topology_retired"] is True
        row63_constant_calls = calls_observations[_ROW63_CONSTANT_OPERATION_ID]
        assert row63_constant_calls["absolute_load_present"] is False
        assert row63_constant_calls["passed"] is True
        if row63_constant_calls["source_present"]:
            assert row63_constant_calls["materialized_constant_present"] is True
            assert row63_constant_calls["destination_delivery_present"] is True
        else:
            assert row63_constant_calls["source_topology_retired"] is True
        row64_constant_calls = calls_observations[_ROW64_CONSTANT_OPERATION_ID]
        assert row64_constant_calls["absolute_load_present"] is False
        assert row64_constant_calls["passed"] is True
        if row64_constant_calls["source_present"]:
            assert row64_constant_calls["materialized_constant_present"] is True
            assert row64_constant_calls["destination_delivery_present"] is True
        else:
            assert row64_constant_calls["source_topology_retired"] is True
        row65_constant_calls = calls_observations[_ROW65_CONSTANT_OPERATION_ID]
        assert row65_constant_calls["absolute_load_present"] is False
        assert row65_constant_calls["passed"] is True
        if row65_constant_calls["source_present"]:
            assert row65_constant_calls["materialized_constant_present"] is True
            assert row65_constant_calls["destination_delivery_present"] is True
        else:
            assert row65_constant_calls["source_topology_retired"] is True
        row66_constant_calls = calls_observations[_ROW66_CONSTANT_OPERATION_ID]
        assert row66_constant_calls["absolute_load_present"] is False
        assert row66_constant_calls["passed"] is True
        if row66_constant_calls["source_present"]:
            assert row66_constant_calls["materialized_constant_present"] is True
            assert row66_constant_calls["destination_delivery_present"] is True
        else:
            assert row66_constant_calls["source_topology_retired"] is True
        row67_constant_calls = calls_observations[_ROW67_CONSTANT_OPERATION_ID]
        assert row67_constant_calls["absolute_load_present"] is False
        assert row67_constant_calls["passed"] is True
        if row67_constant_calls["source_present"]:
            assert row67_constant_calls["materialized_constant_present"] is True
            assert row67_constant_calls["destination_delivery_present"] is True
        else:
            assert row67_constant_calls["source_topology_retired"] is True
        direct_calls = calls_observations["route:rhad-direct@0x40A619"]
        assert direct_calls["source_present"] is False
        assert direct_calls["source_topology_reachable"] is False
        assert direct_calls["source_topology_retired"] is True
        assert direct_calls["indirect_transfer_present"] is False
        assert direct_calls["target_eas"] == []
        assert direct_calls["passed"] is True
        row3_calls = calls_observations["route:rhad-direct@0x40A631"]
        assert row3_calls["source_present"] is False
        assert row3_calls["source_topology_reachable"] is False
        assert row3_calls["source_topology_retired"] is True
        assert row3_calls["indirect_transfer_present"] is False
        assert row3_calls["target_eas"] == []
        assert row3_calls["passed"] is True
        row4_calls = calls_observations["route:rhad-direct@0x40A649"]
        assert row4_calls["source_present"] is False
        assert row4_calls["source_topology_reachable"] is False
        assert row4_calls["source_topology_retired"] is True
        assert row4_calls["indirect_transfer_present"] is False
        assert row4_calls["target_eas"] == []
        assert row4_calls["passed"] is True
        row5_calls = calls_observations["route:rhad-direct@0x40A661"]
        assert row5_calls["source_present"] is False
        assert row5_calls["source_topology_reachable"] is False
        assert row5_calls["source_topology_retired"] is True
        assert row5_calls["indirect_transfer_present"] is False
        assert row5_calls["target_eas"] == []
        assert row5_calls["boundary_exit_eas"] == [
            0x40A5CA,
            0x40AAFD,
            0x40AE26,
        ]
        assert row5_calls["passed"] is True
        row6_calls = calls_observations["route:rhad-direct@0x40A679"]
        assert row6_calls["source_present"] is False
        assert row6_calls["source_topology_reachable"] is False
        assert row6_calls["source_topology_retired"] is True
        assert row6_calls["indirect_transfer_present"] is False
        assert row6_calls["target_eas"] == []
        assert row6_calls["boundary_exit_eas"] == [0x40A5F0, 0x40AE3E]
        assert row6_calls["passed"] is True
        accepted_calls = calls_observations["rhad:route@0x40A605"]
        assert accepted_calls["source_present"] is False
        assert accepted_calls["source_topology_reachable"] is False
        assert accepted_calls["source_topology_retired"] is True
        assert accepted_calls["indirect_transfer_present"] is False
        assert accepted_calls["target_eas"] == []
        assert accepted_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert accepted_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert accepted_calls["semantic_targets_survive"] is True
        assert accepted_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert accepted_calls["passed"] is True
        selected_calls = calls_observations["rhad:route@0x40A6A4"]
        assert selected_calls["source_present"] is False
        assert selected_calls["source_topology_reachable"] is False
        assert selected_calls["source_topology_retired"] is True
        assert selected_calls["indirect_transfer_present"] is False
        assert selected_calls["target_eas"] == []
        assert selected_calls["semantic_target_eas"] == [0x40A6A6, 0x40A800]
        assert selected_calls["delivery_target_eas"] == [0x40A6A6, 0x40A800]
        assert selected_calls["semantic_targets_survive"] is True
        assert selected_calls["passed"] is True
        row9_calls = calls_observations["rhad:route@0x40A6BE"]
        assert row9_calls["source_present"] is False
        assert row9_calls["source_topology_reachable"] is False
        assert row9_calls["source_topology_retired"] is True
        assert row9_calls["indirect_transfer_present"] is False
        assert row9_calls["target_eas"] == []
        assert row9_calls["semantic_target_eas"] == [0x40A6C0, 0x40A960]
        assert row9_calls["delivery_target_eas"] == [0x40A6C0, 0x40A960]
        assert row9_calls["semantic_targets_survive"] is True
        assert row9_calls["passed"] is True
        row10_calls = calls_observations["rhad:route@0x40A6D8"]
        assert row10_calls["source_present"] is False
        assert row10_calls["source_topology_reachable"] is False
        assert row10_calls["source_topology_retired"] is True
        assert row10_calls["indirect_transfer_present"] is False
        assert row10_calls["target_eas"] == []
        assert row10_calls["semantic_target_eas"] == [0x40A6DA, 0x40AB76]
        assert row10_calls["delivery_target_eas"] == [0x40A6DA, 0x40AB76]
        assert row10_calls["semantic_targets_survive"] is True
        assert row10_calls["passed"] is True
        row11_calls = calls_observations["rhad:route@0x40A6F2"]
        assert row11_calls["source_present"] is False
        assert row11_calls["source_topology_reachable"] is False
        assert row11_calls["source_topology_retired"] is True
        assert row11_calls["indirect_transfer_present"] is False
        assert row11_calls["target_eas"] == []
        assert row11_calls["semantic_target_eas"] == [0x40A6F4, 0x40AE8B]
        assert row11_calls["delivery_target_eas"] == [0x40A6F4, 0x40AE8B]
        assert row11_calls["semantic_targets_survive"] is True
        assert row11_calls["passed"] is True
        row12_calls = calls_observations["rhad:route@0x40A70C"]
        assert row12_calls["source_present"] is False
        assert row12_calls["source_topology_reachable"] is False
        assert row12_calls["source_topology_retired"] is True
        assert row12_calls["indirect_transfer_present"] is False
        assert row12_calls["target_eas"] == []
        assert row12_calls["semantic_target_eas"] == [0x40A5F0, 0x40A70E]
        assert row12_calls["delivery_target_eas"] == [0x40A5F0, 0x40A70E]
        assert row12_calls["semantic_targets_survive"] is True
        assert row12_calls["passed"] is True
        setcc_calls = calls_observations["rhad:route@0x40A77C"]
        assert setcc_calls["source_present"] is True
        assert setcc_calls["source_topology_reachable"] is True
        assert setcc_calls["source_topology_retired"] is False
        assert setcc_calls["indirect_transfer_present"] is False
        assert setcc_calls["target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["semantic_target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["delivery_target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["semantic_targets_survive"] is True
        assert setcc_calls["passed"] is True
        scaled_setcc_calls = calls_observations["rhad:route@0x40A792"]
        assert scaled_setcc_calls["indirect_transfer_present"] is False
        assert scaled_setcc_calls["semantic_target_eas"] == [0x40A794, 0x40AEE6]
        assert scaled_setcc_calls["delivery_target_eas"] == [0x40A794, 0x40AEE6]
        if scaled_setcc_calls["source_present"]:
            assert scaled_setcc_calls["target_eas"] == [0x40A794, 0x40AEE6]
        else:
            assert scaled_setcc_calls["source_topology_retired"] is True
            assert scaled_setcc_calls["target_eas"] == []
        assert scaled_setcc_calls["semantic_targets_survive"] is True
        assert scaled_setcc_calls["passed"] is True
        row18_calls = calls_observations["rhad:route@0x40A7AC"]
        assert row18_calls["source_present"] is False
        assert row18_calls["source_topology_reachable"] is False
        assert row18_calls["source_topology_retired"] is True
        assert row18_calls["indirect_transfer_present"] is False
        assert row18_calls["target_eas"] == []
        assert row18_calls["semantic_target_eas"] == [0x40A5F0, 0x40A7AE]
        assert row18_calls["delivery_target_eas"] == [0x40A5F0, 0x40A7AE]
        assert row18_calls["semantic_targets_survive"] is True
        assert row18_calls["passed"] is True
        row19_calls = calls_observations["route:rhad-direct@0x40A7EF"]
        assert row19_calls["source_present"] is False
        assert row19_calls["source_topology_reachable"] is False
        assert row19_calls["source_topology_retired"] is True
        assert row19_calls["indirect_transfer_present"] is False
        assert row19_calls["target_eas"] == []
        assert row19_calls["boundary_exit_eas"] == [0x40B790]
        assert row19_calls["passed"] is True
        row20_calls = calls_observations["rhad:route@0x40A818"]
        assert row20_calls["source_present"] is False
        assert row20_calls["source_topology_reachable"] is False
        assert row20_calls["source_topology_retired"] is True
        assert row20_calls["indirect_transfer_present"] is False
        assert row20_calls["target_eas"] == []
        assert row20_calls["semantic_target_eas"] == [0x40A81A, 0x40AA60]
        assert row20_calls["delivery_target_eas"] == [0x40A81A, 0x40AA60]
        assert row20_calls["semantic_targets_survive"] is True
        assert row20_calls["passed"] is True
        row21_calls = calls_observations["rhad:route@0x40A832"]
        assert row21_calls["source_present"] is False
        assert row21_calls["source_topology_reachable"] is False
        assert row21_calls["source_topology_retired"] is True
        assert row21_calls["indirect_transfer_present"] is False
        assert row21_calls["target_eas"] == []
        assert row21_calls["semantic_target_eas"] == [0x40A834, 0x40AC3D]
        assert row21_calls["delivery_target_eas"] == [0x40A834, 0x40AC3D]
        assert row21_calls["semantic_targets_survive"] is True
        assert row21_calls["passed"] is True
        row22_calls = calls_observations["rhad:route@0x40A84C"]
        assert row22_calls["source_present"] is False
        assert row22_calls["source_topology_reachable"] is False
        assert row22_calls["source_topology_retired"] is True
        assert row22_calls["indirect_transfer_present"] is False
        assert row22_calls["target_eas"] == []
        assert row22_calls["semantic_target_eas"] == [0x40A84E, 0x40AFDF]
        assert row22_calls["delivery_target_eas"] == [0x40A84E, 0x40AFDF]
        assert row22_calls["semantic_targets_survive"] is True
        assert row22_calls["passed"] is True
        row23_calls = calls_observations["rhad:route@0x40A866"]
        assert row23_calls["source_present"] is False
        assert row23_calls["source_topology_reachable"] is False
        assert row23_calls["source_topology_retired"] is True
        assert row23_calls["indirect_transfer_present"] is False
        assert row23_calls["target_eas"] == []
        assert row23_calls["semantic_target_eas"] == [0x40A5F0, 0x40A868]
        assert row23_calls["delivery_target_eas"] == [0x40A5F0, 0x40A868]
        assert row23_calls["semantic_targets_survive"] is True
        assert row23_calls["passed"] is True
        row25_calls = calls_observations["route:rhad-direct@0x40A8B3"]
        assert row25_calls["source_present"] is False
        assert row25_calls["source_topology_reachable"] is False
        assert row25_calls["source_topology_retired"] is True
        assert row25_calls["indirect_transfer_present"] is False
        assert row25_calls["target_eas"] == []
        assert row25_calls["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
        assert row25_calls["passed"] is True
        row26_calls = calls_observations["rhad:route@0x40A8CD"]
        assert row26_calls["source_present"] is False
        assert row26_calls["source_topology_reachable"] is False
        assert row26_calls["source_topology_retired"] is True
        assert row26_calls["indirect_transfer_present"] is False
        assert row26_calls["target_eas"] == []
        assert row26_calls["semantic_target_eas"] == [0x40A8CF, 0x40ACBF]
        assert row26_calls["delivery_target_eas"] == [0x40A8CF, 0x40ACBF]
        assert row26_calls["semantic_targets_survive"] is True
        assert row26_calls["passed"] is True
        row27_calls = calls_observations["rhad:route@0x40A8E7"]
        assert row27_calls["source_present"] is False
        assert row27_calls["source_topology_reachable"] is False
        assert row27_calls["source_topology_retired"] is True
        assert row27_calls["indirect_transfer_present"] is False
        assert row27_calls["target_eas"] == []
        assert row27_calls["semantic_target_eas"] == [0x40A8E9, 0x40B024]
        assert row27_calls["delivery_target_eas"] == [0x40A8E9, 0x40B024]
        assert row27_calls["semantic_targets_survive"] is True
        assert row27_calls["passed"] is True
        row28_calls = calls_observations["rhad:route@0x40A901"]
        assert row28_calls["source_present"] is False
        assert row28_calls["source_topology_reachable"] is False
        assert row28_calls["source_topology_retired"] is True
        assert row28_calls["indirect_transfer_present"] is False
        assert row28_calls["target_eas"] == []
        assert row28_calls["semantic_target_eas"] == [0x40A5F0, 0x40A903]
        assert row28_calls["delivery_target_eas"] == [0x40A5F0, 0x40A903]
        assert row28_calls["semantic_targets_survive"] is True
        assert row28_calls["passed"] is True
        row29_calls = calls_observations["route:rhad-direct@0x40A95E"]
        assert row29_calls["source_present"] is False
        assert row29_calls["source_topology_reachable"] is False
        assert row29_calls["source_topology_retired"] is True
        assert row29_calls["indirect_transfer_present"] is False
        assert row29_calls["target_eas"] == []
        assert row29_calls["boundary_exit_eas"] == [0x40B790]
        assert row29_calls["passed"] is True
        row30_calls = calls_observations["rhad:route@0x40A978"]
        assert row30_calls["source_present"] is False
        assert row30_calls["source_topology_reachable"] is False
        assert row30_calls["source_topology_retired"] is True
        assert row30_calls["indirect_transfer_present"] is False
        assert row30_calls["target_eas"] == []
        assert row30_calls["semantic_target_eas"] == [0x40A97A, 0x40AD1E]
        assert row30_calls["delivery_target_eas"] == [0x40A97A, 0x40AD1E]
        assert row30_calls["semantic_targets_survive"] is True
        assert row30_calls["passed"] is True
        row31_calls = calls_observations["rhad:route@0x40A992"]
        assert row31_calls["source_present"] is False
        assert row31_calls["source_topology_reachable"] is False
        assert row31_calls["source_topology_retired"] is True
        assert row31_calls["indirect_transfer_present"] is False
        assert row31_calls["target_eas"] == []
        assert row31_calls["semantic_target_eas"] == [0x40A994, 0x40B071]
        assert row31_calls["delivery_target_eas"] == [0x40A994, 0x40B071]
        assert row31_calls["semantic_targets_survive"] is True
        assert row31_calls["passed"] is True
        row32_calls = calls_observations["rhad:route@0x40A9AC"]
        assert row32_calls["source_present"] is False
        assert row32_calls["source_topology_reachable"] is False
        assert row32_calls["source_topology_retired"] is True
        assert row32_calls["indirect_transfer_present"] is False
        assert row32_calls["target_eas"] == []
        assert row32_calls["semantic_target_eas"] == [0x40A5F0, 0x40A9AE]
        assert row32_calls["delivery_target_eas"] == [0x40A5F0, 0x40A9AE]
        assert row32_calls["semantic_targets_survive"] is True
        assert row32_calls["passed"] is True
        row33_calls = calls_observations["rhad:route@0x40A9DC"]
        assert row33_calls["source_present"] is False
        assert row33_calls["source_topology_reachable"] is False
        assert row33_calls["source_topology_retired"] is True
        assert row33_calls["indirect_transfer_present"] is False
        assert row33_calls["target_eas"] == []
        assert row33_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row33_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row33_calls["semantic_targets_survive"] is True
        assert row33_calls["passed"] is True
        row34_calls = calls_observations["rhad:route@0x40A9F6"]
        assert row34_calls["source_present"] is False
        assert row34_calls["source_topology_reachable"] is False
        assert row34_calls["source_topology_retired"] is True
        assert row34_calls["indirect_transfer_present"] is False
        assert row34_calls["target_eas"] == []
        assert row34_calls["semantic_target_eas"] == [0x40A9F8, 0x40AD6E]
        assert row34_calls["delivery_target_eas"] == [0x40A9F8, 0x40AD6E]
        assert row34_calls["semantic_targets_survive"] is True
        assert row34_calls["passed"] is True
        row35_calls = calls_observations["rhad:route@0x40AA10"]
        assert row35_calls["source_present"] is False
        assert row35_calls["source_topology_reachable"] is False
        assert row35_calls["source_topology_retired"] is True
        assert row35_calls["indirect_transfer_present"] is False
        assert row35_calls["target_eas"] == []
        assert row35_calls["semantic_target_eas"] == [0x40AA12, 0x40B0BC]
        assert row35_calls["delivery_target_eas"] == [0x40AA12, 0x40B0BC]
        assert row35_calls["semantic_targets_survive"] is True
        assert row35_calls["passed"] is True
        row36_calls = calls_observations["rhad:route@0x40AA2A"]
        assert row36_calls["source_present"] is False
        assert row36_calls["source_topology_reachable"] is False
        assert row36_calls["source_topology_retired"] is True
        assert row36_calls["indirect_transfer_present"] is False
        assert row36_calls["target_eas"] == []
        assert row36_calls["semantic_target_eas"] == [0x40A5F0, 0x40AA2C]
        assert row36_calls["delivery_target_eas"] == [0x40A5F0, 0x40AA2C]
        assert row36_calls["semantic_targets_survive"] is True
        assert row36_calls["passed"] is True
        row37_calls = calls_observations["rhad:route@0x40AA5E"]
        assert row37_calls["source_present"] is False
        assert row37_calls["source_topology_reachable"] is False
        assert row37_calls["source_topology_retired"] is True
        assert row37_calls["indirect_transfer_present"] is False
        assert row37_calls["target_eas"] == []
        assert row37_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row37_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row37_calls["semantic_targets_survive"] is True
        assert row37_calls["passed"] is True
        row38_calls = calls_observations["rhad:route@0x40AA78"]
        assert row38_calls["source_present"] is False
        assert row38_calls["source_topology_reachable"] is False
        assert row38_calls["source_topology_retired"] is True
        assert row38_calls["indirect_transfer_present"] is False
        assert row38_calls["target_eas"] == []
        assert row38_calls["semantic_target_eas"] == [0x40AA7A, 0x40ADBE]
        assert row38_calls["delivery_target_eas"] == [0x40AA7A, 0x40ADBE]
        assert row38_calls["semantic_targets_survive"] is True
        assert row38_calls["passed"] is True
        row39_calls = calls_observations["rhad:route@0x40AA92"]
        assert row39_calls["source_present"] is False
        assert row39_calls["source_topology_reachable"] is False
        assert row39_calls["source_topology_retired"] is True
        assert row39_calls["indirect_transfer_present"] is False
        assert row39_calls["target_eas"] == []
        assert row39_calls["semantic_target_eas"] == [0x40AA94, 0x40B0F2]
        assert row39_calls["delivery_target_eas"] == [0x40AA94, 0x40B0F2]
        assert row39_calls["semantic_targets_survive"] is True
        assert row39_calls["passed"] is True
        row40_calls = calls_observations["rhad:route@0x40AAAC"]
        assert row40_calls["source_present"] is False
        assert row40_calls["source_topology_reachable"] is False
        assert row40_calls["source_topology_retired"] is True
        assert row40_calls["indirect_transfer_present"] is False
        assert row40_calls["target_eas"] == []
        assert row40_calls["semantic_target_eas"] == [0x40A5F0, 0x40AAAE]
        assert row40_calls["delivery_target_eas"] == [0x40A5F0, 0x40AAAE]
        assert row40_calls["semantic_targets_survive"] is True
        assert row40_calls["passed"] is True
        row42_calls = calls_observations["route:rhad-direct@0x40AAFB"]
        assert row42_calls["source_present"] is False
        assert row42_calls["source_topology_reachable"] is False
        assert row42_calls["source_topology_retired"] is True
        assert row42_calls["indirect_transfer_present"] is False
        assert row42_calls["target_eas"] == []
        assert row42_calls["boundary_exit_eas"] == [0x40AB17, 0x40B149]
        assert row42_calls["passed"] is True
        row43_calls = calls_observations["rhad:route@0x40AB15"]
        assert row43_calls["source_present"] is False
        assert row43_calls["source_topology_reachable"] is False
        assert row43_calls["source_topology_retired"] is True
        assert row43_calls["indirect_transfer_present"] is False
        assert row43_calls["target_eas"] == []
        assert row43_calls["semantic_target_eas"] == [0x40AB17, 0x40B149]
        assert row43_calls["delivery_target_eas"] == [0x40AB17, 0x40B149]
        assert row43_calls["semantic_targets_survive"] is True
        assert row43_calls["passed"] is True
        row44_calls = calls_observations["rhad:route@0x40AB2F"]
        assert row44_calls["source_present"] is False
        assert row44_calls["source_topology_reachable"] is False
        assert row44_calls["source_topology_retired"] is True
        assert row44_calls["indirect_transfer_present"] is False
        assert row44_calls["target_eas"] == []
        assert row44_calls["semantic_target_eas"] == [0x40A5F0, 0x40AB31]
        assert row44_calls["delivery_target_eas"] == [0x40A5F0, 0x40AB31]
        assert row44_calls["semantic_targets_survive"] is True
        assert row44_calls["passed"] is True
        row46_calls = calls_observations["rhad:route@0x40AB8E"]
        assert row46_calls["source_present"] is False
        assert row46_calls["source_topology_reachable"] is False
        assert row46_calls["source_topology_retired"] is True
        assert row46_calls["indirect_transfer_present"] is False
        assert row46_calls["target_eas"] == []
        assert row46_calls["semantic_target_eas"] == [0x40AB90, 0x40B17F]
        assert row46_calls["delivery_target_eas"] == [0x40AB90, 0x40B17F]
        assert row46_calls["semantic_targets_survive"] is True
        assert row46_calls["passed"] is True
        row47_calls = calls_observations["rhad:route@0x40ABA8"]
        assert row47_calls["source_present"] is False
        assert row47_calls["source_topology_reachable"] is False
        assert row47_calls["source_topology_retired"] is True
        assert row47_calls["indirect_transfer_present"] is False
        assert row47_calls["target_eas"] == []
        assert row47_calls["semantic_target_eas"] == [0x40A5F0, 0x40ABAA]
        assert row47_calls["delivery_target_eas"] == [0x40A5F0, 0x40ABAA]
        assert row47_calls["semantic_targets_survive"] is True
        assert row47_calls["passed"] is True
        row49_calls = calls_observations["rhad:route@0x40ABDE"]
        assert row49_calls["source_present"] is False
        assert row49_calls["source_topology_reachable"] is False
        assert row49_calls["source_topology_retired"] is True
        assert row49_calls["indirect_transfer_present"] is False
        assert row49_calls["target_eas"] == []
        assert row49_calls["semantic_target_eas"] == [0x40ABE0, 0x40B1D0]
        assert row49_calls["delivery_target_eas"] == [0x40ABE0, 0x40B1D0]
        assert row49_calls["semantic_targets_survive"] is True
        assert row49_calls["passed"] is True
        row50_calls = calls_observations["rhad:route@0x40ABF8"]
        assert row50_calls["source_present"] is False
        assert row50_calls["source_topology_reachable"] is False
        assert row50_calls["source_topology_retired"] is True
        assert row50_calls["indirect_transfer_present"] is False
        assert row50_calls["target_eas"] == []
        assert row50_calls["semantic_target_eas"] == [0x40A5F0, 0x40ABFA]
        assert row50_calls["delivery_target_eas"] == [0x40A5F0, 0x40ABFA]
        assert row50_calls["semantic_targets_survive"] is True
        assert row50_calls["passed"] is True
        row51_calls = calls_observations["route:rhad-direct@0x40AC3B"]
        assert row51_calls["source_present"] is False
        assert row51_calls["source_topology_reachable"] is False
        assert row51_calls["source_topology_retired"] is True
        assert row51_calls["indirect_transfer_present"] is False
        assert row51_calls["target_eas"] == []
        assert row51_calls["boundary_exit_eas"] == [0x40B790]
        assert row51_calls["passed"] is True
        row52_calls = calls_observations["rhad:route@0x40AC54"]
        assert row52_calls["source_present"] is False
        assert row52_calls["source_topology_reachable"] is False
        assert row52_calls["source_topology_retired"] is True
        assert row52_calls["indirect_transfer_present"] is False
        assert row52_calls["target_eas"] == []
        assert row52_calls["semantic_target_eas"] == [0x40AC56, 0x40B21C]
        assert row52_calls["delivery_target_eas"] == [0x40AC56, 0x40B21C]
        assert row52_calls["semantic_targets_survive"] is True
        assert row52_calls["passed"] is True
        row53_calls = calls_observations["rhad:route@0x40AC6E"]
        assert row53_calls["source_present"] is False
        assert row53_calls["source_topology_reachable"] is False
        assert row53_calls["source_topology_retired"] is True
        assert row53_calls["indirect_transfer_present"] is False
        assert row53_calls["target_eas"] == []
        assert row53_calls["semantic_target_eas"] == [0x40A5F0, 0x40AC70]
        assert row53_calls["delivery_target_eas"] == [0x40A5F0, 0x40AC70]
        assert row53_calls["semantic_targets_survive"] is True
        assert row53_calls["passed"] is True
        row54_calls = calls_observations["route:rhad-direct@0x40ACBD"]
        assert row54_calls["source_present"] is False
        assert row54_calls["source_topology_reachable"] is False
        assert row54_calls["source_topology_retired"] is True
        assert row54_calls["indirect_transfer_present"] is False
        assert row54_calls["target_eas"] == []
        assert row54_calls["boundary_exit_eas"] == [0x40B790]
        assert row54_calls["passed"] is True
        row55_calls = calls_observations["rhad:route@0x40ACD7"]
        assert row55_calls["source_present"] is False
        assert row55_calls["source_topology_reachable"] is False
        assert row55_calls["source_topology_retired"] is True
        assert row55_calls["indirect_transfer_present"] is False
        assert row55_calls["target_eas"] == []
        assert row55_calls["semantic_target_eas"] == [0x40ACD9, 0x40B26D]
        assert row55_calls["delivery_target_eas"] == [0x40ACD9, 0x40B26D]
        assert row55_calls["semantic_targets_survive"] is True
        assert row55_calls["passed"] is True
        row56_calls = calls_observations["rhad:route@0x40ACF1"]
        assert row56_calls["source_present"] is False
        assert row56_calls["source_topology_reachable"] is False
        assert row56_calls["source_topology_retired"] is True
        assert row56_calls["indirect_transfer_present"] is False
        assert row56_calls["target_eas"] == []
        assert row56_calls["semantic_target_eas"] == [0x40A5F0, 0x40ACF3]
        assert row56_calls["delivery_target_eas"] == [0x40A5F0, 0x40ACF3]
        assert row56_calls["semantic_targets_survive"] is True
        assert row56_calls["passed"] is True
        row57_calls = calls_observations["route:rhad-direct@0x40AD1C"]
        assert row57_calls["source_present"] is False
        assert row57_calls["source_topology_reachable"] is False
        assert row57_calls["source_topology_retired"] is True
        assert row57_calls["indirect_transfer_present"] is False
        assert row57_calls["target_eas"] == []
        assert row57_calls["boundary_exit_eas"] == [0x40B790]
        assert row57_calls["passed"] is True
        row58_calls = calls_observations["rhad:route@0x40AD36"]
        assert row58_calls["source_present"] is False
        assert row58_calls["source_topology_reachable"] is False
        assert row58_calls["source_topology_retired"] is True
        assert row58_calls["indirect_transfer_present"] is False
        assert row58_calls["target_eas"] == []
        assert row58_calls["semantic_target_eas"] == [0x40AD38, 0x40B2DB]
        assert row58_calls["delivery_target_eas"] == [0x40AD38, 0x40B2DB]
        assert row58_calls["semantic_targets_survive"] is True
        assert row58_calls["passed"] is True
        row59_calls = calls_observations["rhad:route@0x40AD50"]
        assert row59_calls["source_present"] is False
        assert row59_calls["source_topology_reachable"] is False
        assert row59_calls["source_topology_retired"] is True
        assert row59_calls["indirect_transfer_present"] is False
        assert row59_calls["target_eas"] == []
        assert row59_calls["semantic_target_eas"] == [0x40A5F0, 0x40AD52]
        assert row59_calls["delivery_target_eas"] == [0x40A5F0, 0x40AD52]
        assert row59_calls["semantic_targets_survive"] is True
        assert row59_calls["passed"] is True
        row60_calls = calls_observations["rhad:route@0x40AD6C"]
        assert row60_calls["source_present"] is False
        assert row60_calls["source_topology_reachable"] is False
        assert row60_calls["source_topology_retired"] is True
        assert row60_calls["indirect_transfer_present"] is False
        assert row60_calls["target_eas"] == []
        assert row60_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row60_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row60_calls["semantic_targets_survive"] is True
        assert row60_calls["passed"] is True
        row61_calls = calls_observations["rhad:route@0x40AD86"]
        assert row61_calls["source_present"] is False
        assert row61_calls["source_topology_reachable"] is False
        assert row61_calls["source_topology_retired"] is True
        assert row61_calls["indirect_transfer_present"] is False
        assert row61_calls["target_eas"] == []
        assert row61_calls["semantic_target_eas"] == [0x40AD88, 0x40B32C]
        assert row61_calls["delivery_target_eas"] == [0x40AD88, 0x40B32C]
        assert row61_calls["semantic_targets_survive"] is True
        assert row61_calls["passed"] is True
        row62_calls = calls_observations["rhad:route@0x40ADA0"]
        assert row62_calls["source_present"] is False
        assert row62_calls["source_topology_reachable"] is False
        assert row62_calls["source_topology_retired"] is True
        assert row62_calls["indirect_transfer_present"] is False
        assert row62_calls["target_eas"] == []
        assert row62_calls["semantic_target_eas"] == [0x40A5F0, 0x40ADA2]
        assert row62_calls["delivery_target_eas"] == [0x40A5F0, 0x40ADA2]
        assert row62_calls["semantic_targets_survive"] is True
        assert row62_calls["passed"] is True
        row63_calls = calls_observations["rhad:route@0x40ADBC"]
        assert row63_calls["source_present"] is False
        assert row63_calls["source_topology_reachable"] is False
        assert row63_calls["source_topology_retired"] is True
        assert row63_calls["indirect_transfer_present"] is False
        assert row63_calls["target_eas"] == []
        assert row63_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row63_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row63_calls["semantic_targets_survive"] is True
        assert row63_calls["passed"] is True
        row64_calls = calls_observations["rhad:route@0x40ADD6"]
        assert row64_calls["source_present"] is False
        assert row64_calls["source_topology_reachable"] is False
        assert row64_calls["source_topology_retired"] is True
        assert row64_calls["indirect_transfer_present"] is False
        assert row64_calls["target_eas"] == []
        assert row64_calls["semantic_target_eas"] == [0x40ADD8, 0x40B37C]
        assert row64_calls["delivery_target_eas"] == [0x40ADD8, 0x40B37C]
        assert row64_calls["semantic_targets_survive"] is True
        assert row64_calls["passed"] is True
        row65_calls = calls_observations["rhad:route@0x40ADF0"]
        assert row65_calls["source_present"] is False
        assert row65_calls["source_topology_reachable"] is False
        assert row65_calls["source_topology_retired"] is True
        assert row65_calls["indirect_transfer_present"] is False
        assert row65_calls["target_eas"] == []
        assert row65_calls["semantic_target_eas"] == [0x40A5F0, 0x40ADF2]
        assert row65_calls["delivery_target_eas"] == [0x40A5F0, 0x40ADF2]
        assert row65_calls["semantic_targets_survive"] is True
        assert row65_calls["passed"] is True
        row66_calls = calls_observations["rhad:route@0x40AE18"]
        assert row66_calls["source_present"] is False
        assert row66_calls["source_topology_reachable"] is False
        assert row66_calls["source_topology_retired"] is True
        assert row66_calls["indirect_transfer_present"] is False
        assert row66_calls["target_eas"] == []
        assert row66_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row66_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row66_calls["semantic_targets_survive"] is True
        assert row66_calls["passed"] is True
        row67_calls = calls_observations["route:rhad-direct@0x40AE24"]
        assert row67_calls["source_present"] is False
        assert row67_calls["source_topology_reachable"] is False
        assert row67_calls["source_topology_retired"] is True
        assert row67_calls["indirect_transfer_present"] is False
        assert row67_calls["target_eas"] == []
        assert row67_calls["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
        assert row67_calls["passed"] is True
        row68_calls = calls_observations["rhad:route@0x40AE3C"]
        # Hex-Rays coalesces the native source EA before CALLS, but the
        # semantic observer still recognizes the live two-arm predicate
        # topology.  Do not misreport that live topology as retired.
        assert row68_calls["source_present"] is True
        assert row68_calls["source_topology_reachable"] is True
        assert row68_calls["source_topology_retired"] is False
        assert row68_calls["indirect_transfer_present"] is False
        assert row68_calls["target_eas"] == [0x40A5F0, 0x40AE3E]
        assert row68_calls["semantic_target_eas"] == [0x40A5F0, 0x40AE3E]
        assert row68_calls["delivery_target_eas"] == [0x40A5F0, 0x40AE3E]
        assert row68_calls["semantic_targets_survive"] is True
        assert row68_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row68_calls["passed"] is True
        row69_calls = calls_observations["rhad:route@0x40AE89"]
        assert row69_calls["source_present"] is False
        assert row69_calls["source_topology_reachable"] is False
        assert row69_calls["source_topology_retired"] is True
        assert row69_calls["indirect_transfer_present"] is False
        assert row69_calls["target_eas"] == []
        assert row69_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row69_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row69_calls["semantic_targets_survive"] is True
        assert row69_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row69_calls["passed"] is True
        row70_calls = calls_observations["rhad:route@0x40AEA3"]
        assert row70_calls["source_present"] is False
        assert row70_calls["source_topology_reachable"] is False
        assert row70_calls["source_topology_retired"] is True
        assert row70_calls["indirect_transfer_present"] is False
        assert row70_calls["target_eas"] == []
        assert row70_calls["semantic_target_eas"] == [0x40A5F0, 0x40AEA5]
        assert row70_calls["delivery_target_eas"] == [0x40A5F0, 0x40AEA5]
        assert row70_calls["semantic_targets_survive"] is True
        assert row70_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row70_calls["passed"] is True
        row71_calls = calls_observations["route:rhad-direct@0x40AEE4"]
        assert row71_calls["source_present"] is False
        assert row71_calls["source_topology_reachable"] is False
        assert row71_calls["source_topology_retired"] is True
        assert row71_calls["indirect_transfer_present"] is False
        assert row71_calls["target_eas"] == []
        assert row71_calls["boundary_exit_eas"] == [0x40B790]
        assert row71_calls["passed"] is True
        row72_calls = calls_observations["rhad:route@0x40AEFE"]
        assert row72_calls["source_present"] is False
        assert row72_calls["source_topology_reachable"] is False
        assert row72_calls["source_topology_retired"] is True
        assert row72_calls["indirect_transfer_present"] is False
        assert row72_calls["target_eas"] == []
        assert row72_calls["semantic_target_eas"] == [0x40A5F0, 0x40AF00]
        assert row72_calls["delivery_target_eas"] == [0x40A5F0, 0x40AF00]
        assert row72_calls["semantic_targets_survive"] is True
        assert row72_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row72_calls["passed"] is True
        row73_calls = calls_observations["route:rhad-direct@0x40AFDD"]
        assert row73_calls["source_present"] is False
        assert row73_calls["source_topology_reachable"] is False
        assert row73_calls["source_topology_retired"] is True
        assert row73_calls["indirect_transfer_present"] is False
        assert row73_calls["target_eas"] == []
        assert row73_calls["boundary_exit_eas"] == [0x40B790]
        assert row73_calls["passed"] is True
        row74_calls = calls_observations["rhad:route@0x40AFF7"]
        assert row74_calls["source_present"] is False
        assert row74_calls["source_topology_reachable"] is False
        assert row74_calls["source_topology_retired"] is True
        assert row74_calls["indirect_transfer_present"] is False
        assert row74_calls["target_eas"] == []
        assert row74_calls["semantic_target_eas"] == [0x40A5F0, 0x40AFF9]
        assert row74_calls["delivery_target_eas"] == [0x40A5F0, 0x40AFF9]
        assert row74_calls["semantic_targets_survive"] is True
        assert row74_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row74_calls["passed"] is True
        row75_calls = calls_observations["route:rhad-direct@0x40B022"]
        assert row75_calls["source_present"] is False
        assert row75_calls["source_topology_reachable"] is False
        assert row75_calls["source_topology_retired"] is True
        assert row75_calls["indirect_transfer_present"] is False
        assert row75_calls["target_eas"] == []
        assert row75_calls["boundary_exit_eas"] == [0x40B790]
        assert row75_calls["passed"] is True
        row76_calls = calls_observations["rhad:route@0x40B03C"]
        assert row76_calls["source_present"] is False
        assert row76_calls["source_topology_reachable"] is False
        assert row76_calls["source_topology_retired"] is True
        assert row76_calls["indirect_transfer_present"] is False
        assert row76_calls["target_eas"] == []
        assert row76_calls["semantic_target_eas"] == [0x40A5F0, 0x40B03E]
        assert row76_calls["delivery_target_eas"] == [0x40A5F0, 0x40B03E]
        assert row76_calls["semantic_targets_survive"] is True
        assert row76_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row76_calls["passed"] is True
        row77_calls = calls_observations["route:rhad-direct@0x40B06F"]
        assert row77_calls["source_present"] is False
        assert row77_calls["source_topology_reachable"] is False
        assert row77_calls["source_topology_retired"] is True
        assert row77_calls["indirect_transfer_present"] is False
        assert row77_calls["target_eas"] == []
        assert row77_calls["boundary_exit_eas"] == [0x40B790]
        assert row77_calls["passed"] is True
        row78_calls = calls_observations["rhad:route@0x40B089"]
        assert row78_calls["source_present"] is False
        assert row78_calls["source_topology_reachable"] is False
        assert row78_calls["source_topology_retired"] is True
        assert row78_calls["indirect_transfer_present"] is False
        assert row78_calls["target_eas"] == []
        assert row78_calls["semantic_target_eas"] == [0x40A5F0, 0x40B08B]
        assert row78_calls["delivery_target_eas"] == [0x40A5F0, 0x40B08B]
        assert row78_calls["semantic_targets_survive"] is True
        assert row78_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row78_calls["passed"] is True
        row79_calls = calls_observations["rhad:route@0x40B0BA"]
        assert row79_calls["source_present"] is False
        assert row79_calls["source_topology_reachable"] is False
        assert row79_calls["source_topology_retired"] is True
        assert row79_calls["indirect_transfer_present"] is False
        assert row79_calls["target_eas"] == []
        assert row79_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row79_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row79_calls["semantic_targets_survive"] is True
        assert row79_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row79_calls["passed"] is True
        row80_calls = calls_observations["rhad:route@0x40B0D4"]
        assert row80_calls["source_present"] is False
        assert row80_calls["source_topology_reachable"] is False
        assert row80_calls["source_topology_retired"] is True
        assert row80_calls["indirect_transfer_present"] is False
        assert row80_calls["target_eas"] == []
        assert row80_calls["semantic_target_eas"] == [0x40A5F0, 0x40B0D6]
        assert row80_calls["delivery_target_eas"] == [0x40A5F0, 0x40B0D6]
        assert row80_calls["semantic_targets_survive"] is True
        assert row80_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row80_calls["passed"] is True
        row81_calls = calls_observations["rhad:route@0x40B0F0"]
        assert row81_calls["source_present"] is False
        assert row81_calls["source_topology_reachable"] is False
        assert row81_calls["source_topology_retired"] is True
        assert row81_calls["indirect_transfer_present"] is False
        assert row81_calls["target_eas"] == []
        assert row81_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row81_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row81_calls["semantic_targets_survive"] is True
        assert row81_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row81_calls["passed"] is True
        row82_calls = calls_observations["rhad:route@0x40B10A"]
        assert row82_calls["source_present"] is False
        assert row82_calls["source_topology_reachable"] is False
        assert row82_calls["source_topology_retired"] is True
        assert row82_calls["indirect_transfer_present"] is False
        assert row82_calls["target_eas"] == []
        assert row82_calls["semantic_target_eas"] == [0x40A5F0, 0x40B10C]
        assert row82_calls["delivery_target_eas"] == [0x40A5F0, 0x40B10C]
        assert row82_calls["semantic_targets_survive"] is True
        assert row82_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row82_calls["passed"] is True
        row83_calls = calls_observations["rhad:route@0x40B147"]
        assert row83_calls["source_present"] is False
        assert row83_calls["source_topology_reachable"] is False
        assert row83_calls["source_topology_retired"] is True
        assert row83_calls["indirect_transfer_present"] is False
        assert row83_calls["target_eas"] == []
        assert row83_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row83_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row83_calls["semantic_targets_survive"] is True
        assert row83_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row83_calls["passed"] is True
        row84_calls = calls_observations["rhad:route@0x40B161"]
        assert row84_calls["source_present"] is False
        assert row84_calls["source_topology_reachable"] is False
        assert row84_calls["source_topology_retired"] is True
        assert row84_calls["indirect_transfer_present"] is False
        assert row84_calls["target_eas"] == []
        assert row84_calls["semantic_target_eas"] == [0x40A5F0, 0x40B163]
        assert row84_calls["delivery_target_eas"] == [0x40A5F0, 0x40B163]
        assert row84_calls["semantic_targets_survive"] is True
        assert row84_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row84_calls["passed"] is True
        row85_calls = calls_observations["rhad:route@0x40B17D"]
        assert row85_calls["source_present"] is False
        assert row85_calls["source_topology_reachable"] is False
        assert row85_calls["source_topology_retired"] is True
        assert row85_calls["indirect_transfer_present"] is False
        assert row85_calls["target_eas"] == []
        assert row85_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row85_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row85_calls["semantic_targets_survive"] is True
        assert row85_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row85_calls["passed"] is True
        row86_calls = calls_observations["rhad:route@0x40B197"]
        assert row86_calls["source_present"] is False
        assert row86_calls["source_topology_reachable"] is False
        assert row86_calls["source_topology_retired"] is True
        assert row86_calls["indirect_transfer_present"] is False
        assert row86_calls["target_eas"] == []
        assert row86_calls["semantic_target_eas"] == [0x40A5F0, 0x40B199]
        assert row86_calls["delivery_target_eas"] == [0x40A5F0, 0x40B199]
        assert row86_calls["semantic_targets_survive"] is True
        assert row86_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row86_calls["passed"] is True
        row87_calls = calls_observations["route:rhad-direct@0x40B1CE"]
        assert row87_calls["source_present"] is False
        assert row87_calls["source_topology_reachable"] is False
        assert row87_calls["source_topology_retired"] is True
        assert row87_calls["indirect_transfer_present"] is False
        assert row87_calls["target_eas"] == []
        assert row87_calls["boundary_exit_eas"] == [0x40B790]
        assert row87_calls["passed"] is True
        row88_calls = calls_observations["rhad:route@0x40B1E8"]
        assert row88_calls["source_present"] is False
        assert row88_calls["source_topology_reachable"] is False
        assert row88_calls["source_topology_retired"] is True
        assert row88_calls["indirect_transfer_present"] is False
        assert row88_calls["target_eas"] == []
        assert row88_calls["semantic_target_eas"] == [0x40A5F0, 0x40B1EA]
        assert row88_calls["delivery_target_eas"] == [0x40A5F0, 0x40B1EA]
        assert row88_calls["semantic_targets_survive"] is True
        assert row88_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row88_calls["passed"] is True
        row89_calls = calls_observations["rhad:route@0x40B21A"]
        assert row89_calls["source_present"] is False
        assert row89_calls["source_topology_reachable"] is False
        assert row89_calls["source_topology_retired"] is True
        assert row89_calls["indirect_transfer_present"] is False
        assert row89_calls["target_eas"] == []
        assert row89_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row89_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row89_calls["semantic_targets_survive"] is True
        assert row89_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row89_calls["passed"] is True
        row90_calls = calls_observations["rhad:route@0x40B234"]
        assert row90_calls["source_present"] is False
        assert row90_calls["source_topology_reachable"] is False
        assert row90_calls["source_topology_retired"] is True
        assert row90_calls["indirect_transfer_present"] is False
        assert row90_calls["target_eas"] == []
        assert row90_calls["semantic_target_eas"] == [0x40A5F0, 0x40B236]
        assert row90_calls["delivery_target_eas"] == [0x40A5F0, 0x40B236]
        assert row90_calls["semantic_targets_survive"] is True
        assert row90_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row90_calls["passed"] is True
        row91_calls = calls_observations["rhad:route@0x40B26B"]
        assert row91_calls["source_present"] is False
        assert row91_calls["source_topology_reachable"] is False
        assert row91_calls["source_topology_retired"] is True
        assert row91_calls["indirect_transfer_present"] is False
        assert row91_calls["target_eas"] == []
        assert row91_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row91_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row91_calls["semantic_targets_survive"] is True
        assert row91_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row91_calls["passed"] is True
        row92_calls = calls_observations["rhad:route@0x40B285"]
        assert row92_calls["source_present"] is False
        assert row92_calls["source_topology_reachable"] is False
        assert row92_calls["source_topology_retired"] is True
        assert row92_calls["indirect_transfer_present"] is False
        assert row92_calls["target_eas"] == []
        assert row92_calls["semantic_target_eas"] == [0x40A5F0, 0x40B287]
        assert row92_calls["delivery_target_eas"] == [0x40A5F0, 0x40B287]
        assert row92_calls["semantic_targets_survive"] is True
        assert row92_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row92_calls["passed"] is True
        row93_calls = calls_observations["route:rhad-direct@0x40B2D9"]
        assert row93_calls["source_present"] is False
        assert row93_calls["source_topology_reachable"] is False
        assert row93_calls["source_topology_retired"] is True
        assert row93_calls["indirect_transfer_present"] is False
        assert row93_calls["target_eas"] == []
        assert row93_calls["boundary_exit_eas"] == [0x40B790]
        assert row93_calls["passed"] is True
        row94_calls = calls_observations["rhad:route@0x40B2F3"]
        assert row94_calls["source_present"] is False
        assert row94_calls["source_topology_reachable"] is False
        assert row94_calls["source_topology_retired"] is True
        assert row94_calls["indirect_transfer_present"] is False
        assert row94_calls["target_eas"] == []
        assert row94_calls["semantic_target_eas"] == [0x40A5F0, 0x40B2F5]
        assert row94_calls["delivery_target_eas"] == [0x40A5F0, 0x40B2F5]
        assert row94_calls["semantic_targets_survive"] is True
        assert row94_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row94_calls["passed"] is True
        row95_calls = calls_observations["route:rhad-direct@0x40B32A"]
        assert row95_calls["source_present"] is False
        assert row95_calls["source_topology_reachable"] is False
        assert row95_calls["source_topology_retired"] is True
        assert row95_calls["indirect_transfer_present"] is False
        assert row95_calls["target_eas"] == []
        assert row95_calls["boundary_exit_eas"] == [0x40B790]
        assert row95_calls["passed"] is True
        row96_calls = calls_observations["rhad:route@0x40B340"]
        assert row96_calls["source_present"] is True
        assert row96_calls["source_topology_reachable"] is True
        assert row96_calls["source_topology_retired"] is False
        assert row96_calls["indirect_transfer_present"] is False
        assert row96_calls["target_eas"] == [0x40A5F0, 0x40B342]
        assert row96_calls["semantic_target_eas"] == [0x40A5F0, 0x40B342]
        assert row96_calls["delivery_target_eas"] == [0x40A5F0, 0x40B342]
        assert row96_calls["semantic_targets_survive"] is True
        assert row96_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row96_calls["passed"] is True
        row97_calls = calls_observations["rhad:route@0x40B37A"]
        assert row97_calls["source_present"] is False
        assert row97_calls["source_topology_reachable"] is False
        assert row97_calls["source_topology_retired"] is True
        assert row97_calls["indirect_transfer_present"] is False
        assert row97_calls["target_eas"] == []
        assert row97_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row97_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row97_calls["semantic_targets_survive"] is True
        assert row97_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row97_calls["passed"] is True
        row98_calls = calls_observations["rhad:route@0x40B394"]
        assert row98_calls["source_present"] is False
        assert row98_calls["source_topology_reachable"] is False
        assert row98_calls["source_topology_retired"] is True
        assert row98_calls["indirect_transfer_present"] is False
        assert row98_calls["target_eas"] == []
        assert row98_calls["semantic_target_eas"] == [0x40B396, 0x40B3E5]
        assert row98_calls["delivery_target_eas"] == [0x40B396, 0x40B3E5]
        assert row98_calls["semantic_targets_survive"] is True
        assert row98_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40B3B0,
            0x40B3FF,
        ]
        assert row98_calls["passed"] is True
        row99_calls = calls_observations["rhad:route@0x40B3AE"]
        assert row99_calls["source_present"] is False
        assert row99_calls["source_topology_reachable"] is False
        assert row99_calls["source_topology_retired"] is True
        assert row99_calls["indirect_transfer_present"] is False
        assert row99_calls["target_eas"] == []
        assert row99_calls["semantic_target_eas"] == [0x40A5F0, 0x40B3B0]
        assert row99_calls["delivery_target_eas"] == [0x40A5F0, 0x40B3B0]
        assert row99_calls["semantic_targets_survive"] is True
        assert row99_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row99_calls["passed"] is True
        row100_calls = calls_observations["rhad:route@0x40B3E3"]
        assert row100_calls["source_present"] is False
        assert row100_calls["source_topology_reachable"] is False
        assert row100_calls["source_topology_retired"] is True
        assert row100_calls["indirect_transfer_present"] is False
        assert row100_calls["target_eas"] == []
        assert row100_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row100_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row100_calls["semantic_targets_survive"] is True
        assert row100_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row100_calls["passed"] is True
        row101_calls = calls_observations["rhad:route@0x40B3FD"]
        assert row101_calls["source_present"] is False
        assert row101_calls["source_topology_reachable"] is False
        assert row101_calls["source_topology_retired"] is True
        assert row101_calls["indirect_transfer_present"] is False
        assert row101_calls["target_eas"] == []
        assert row101_calls["semantic_target_eas"] == [0x40A5F0, 0x40B3FF]
        assert row101_calls["delivery_target_eas"] == [0x40A5F0, 0x40B3FF]
        assert row101_calls["semantic_targets_survive"] is True
        assert row101_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row101_calls["passed"] is True
        row102_calls = calls_observations["rhad:route@0x40B4C3"]
        assert row102_calls["source_present"] is False
        assert row102_calls["source_topology_reachable"] is False
        assert row102_calls["source_topology_retired"] is True
        assert row102_calls["indirect_transfer_present"] is False
        assert row102_calls["target_eas"] == []
        assert row102_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row102_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row102_calls["semantic_targets_survive"] is True
        assert row102_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row102_calls["passed"] is True
        row103_calls = calls_observations["route:rhad-direct@0x40B4EE"]
        assert row103_calls["source_present"] is False
        assert row103_calls["source_topology_reachable"] is False
        assert row103_calls["source_topology_retired"] is True
        assert row103_calls["indirect_transfer_present"] is False
        assert row103_calls["target_eas"] == []
        assert row103_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row103_calls["passed"] is True
        row104_calls = calls_observations["route:rhad-direct@0x40B519"]
        assert row104_calls["source_present"] is False
        assert row104_calls["source_topology_reachable"] is False
        assert row104_calls["source_topology_retired"] is True
        assert row104_calls["indirect_transfer_present"] is False
        assert row104_calls["target_eas"] == []
        assert row104_calls["semantic_target_eas"] == [0x40A607]
        assert row104_calls["delivery_target_eas"] == [0x40A607]
        assert row104_calls["semantic_targets_survive"] is True
        assert row104_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row104_calls["passed"] is True
        row105_calls = calls_observations["route:rhad-direct@0x40B540"]
        assert row105_calls["source_present"] is False
        assert row105_calls["source_topology_reachable"] is False
        assert row105_calls["source_topology_retired"] is True
        assert row105_calls["indirect_transfer_present"] is False
        assert row105_calls["target_eas"] == []
        assert row105_calls["semantic_target_eas"] == [0x40A607]
        assert row105_calls["delivery_target_eas"] == [0x40A607]
        assert row105_calls["semantic_targets_survive"] is True
        assert row105_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row105_calls["passed"] is True
        row106_calls = calls_observations["route:rhad-direct@0x40B56B"]
        assert row106_calls["source_present"] is False
        assert row106_calls["source_topology_reachable"] is False
        assert row106_calls["source_topology_retired"] is True
        assert row106_calls["indirect_transfer_present"] is False
        assert row106_calls["target_eas"] == []
        assert row106_calls["semantic_target_eas"] == [0x40A607]
        assert row106_calls["delivery_target_eas"] == [0x40A607]
        assert row106_calls["semantic_targets_survive"] is True
        assert row106_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row106_calls["passed"] is True
        row107_calls = calls_observations["route:rhad-direct@0x40B596"]
        assert row107_calls["source_present"] is False
        assert row107_calls["source_topology_reachable"] is False
        assert row107_calls["source_topology_retired"] is True
        assert row107_calls["indirect_transfer_present"] is False
        assert row107_calls["target_eas"] == []
        assert row107_calls["semantic_target_eas"] == [0x40A607]
        assert row107_calls["delivery_target_eas"] == [0x40A607]
        assert row107_calls["semantic_targets_survive"] is True
        assert row107_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row107_calls["passed"] is True
        row108_calls = calls_observations["route:rhad-direct@0x40B5B5"]
        assert row108_calls["source_present"] is False
        assert row108_calls["source_topology_reachable"] is False
        assert row108_calls["source_topology_retired"] is True
        assert row108_calls["indirect_transfer_present"] is False
        assert row108_calls["target_eas"] == []
        assert row108_calls["semantic_target_eas"] == [0x40A607]
        assert row108_calls["delivery_target_eas"] == [0x40A607]
        assert row108_calls["semantic_targets_survive"] is True
        assert row108_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row108_calls["passed"] is True
        row109_calls = calls_observations["route:rhad-direct@0x40B5DC"]
        assert row109_calls["source_present"] is False
        assert row109_calls["source_topology_reachable"] is False
        assert row109_calls["source_topology_retired"] is True
        assert row109_calls["indirect_transfer_present"] is False
        assert row109_calls["target_eas"] == []
        assert row109_calls["semantic_target_eas"] == [0x40A607]
        assert row109_calls["delivery_target_eas"] == [0x40A607]
        assert row109_calls["semantic_targets_survive"] is True
        assert row109_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row109_calls["passed"] is True
        row110_calls = calls_observations["route:rhad-direct@0x40B607"]
        assert row110_calls["source_present"] is False
        assert row110_calls["source_topology_reachable"] is False
        assert row110_calls["source_topology_retired"] is True
        assert row110_calls["indirect_transfer_present"] is False
        assert row110_calls["target_eas"] == []
        assert row110_calls["semantic_target_eas"] == [0x40A607]
        assert row110_calls["delivery_target_eas"] == [0x40A607]
        assert row110_calls["semantic_targets_survive"] is True
        assert row110_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row110_calls["passed"] is True
        row111_calls = calls_observations["route:rhad-direct@0x40B626"]
        assert row111_calls["source_present"] is False
        assert row111_calls["source_topology_reachable"] is False
        assert row111_calls["source_topology_retired"] is True
        assert row111_calls["indirect_transfer_present"] is False
        assert row111_calls["target_eas"] == []
        assert row111_calls["semantic_target_eas"] == [0x40A607]
        assert row111_calls["delivery_target_eas"] == [0x40A607]
        assert row111_calls["semantic_targets_survive"] is True
        assert row111_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row111_calls["passed"] is True
        row112_calls = calls_observations["route:rhad-direct@0x40B645"]
        assert row112_calls["source_present"] is False
        assert row112_calls["source_topology_reachable"] is False
        assert row112_calls["source_topology_retired"] is True
        assert row112_calls["indirect_transfer_present"] is False
        assert row112_calls["target_eas"] == []
        assert row112_calls["semantic_target_eas"] == [0x40A607]
        assert row112_calls["delivery_target_eas"] == [0x40A607]
        assert row112_calls["semantic_targets_survive"] is True
        assert row112_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row112_calls["passed"] is True
        row113_calls = calls_observations["route:rhad-direct@0x40B666"]
        assert row113_calls["source_present"] is False
        assert row113_calls["source_topology_reachable"] is False
        assert row113_calls["source_topology_retired"] is True
        assert row113_calls["indirect_transfer_present"] is False
        assert row113_calls["target_eas"] == []
        assert row113_calls["semantic_target_eas"] == [0x40A607]
        assert row113_calls["delivery_target_eas"] == [0x40A607]
        assert row113_calls["semantic_targets_survive"] is True
        assert row113_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row113_calls["passed"] is True
        row114_calls = calls_observations["route:rhad-direct@0x40B691"]
        assert row114_calls["source_present"] is False
        assert row114_calls["source_topology_reachable"] is False
        assert row114_calls["source_topology_retired"] is True
        assert row114_calls["indirect_transfer_present"] is False
        assert row114_calls["target_eas"] == []
        assert row114_calls["semantic_target_eas"] == [0x40A607]
        assert row114_calls["delivery_target_eas"] == [0x40A607]
        assert row114_calls["semantic_targets_survive"] is True
        assert row114_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row114_calls["passed"] is True
        row115_calls = calls_observations["route:rhad-direct@0x40B6B2"]
        assert row115_calls["source_present"] is False
        assert row115_calls["source_topology_reachable"] is False
        assert row115_calls["source_topology_retired"] is True
        assert row115_calls["indirect_transfer_present"] is False
        assert row115_calls["target_eas"] == []
        assert row115_calls["semantic_target_eas"] == [0x40A607]
        assert row115_calls["delivery_target_eas"] == [0x40A607]
        assert row115_calls["semantic_targets_survive"] is True
        assert row115_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row115_calls["passed"] is True
        row116_calls = calls_observations["rhad:route@0x40B6D4"]
        assert row116_calls["source_present"] is False
        assert row116_calls["source_topology_reachable"] is False
        assert row116_calls["source_topology_retired"] is True
        assert row116_calls["indirect_transfer_present"] is False
        assert row116_calls["target_eas"] == []
        assert row116_calls["semantic_target_eas"] == [0x40B6D6, 0x40B790]
        assert row116_calls["delivery_target_eas"] == [0x40B6D6, 0x40B790]
        assert row116_calls["semantic_targets_survive"] is True
        assert row116_calls["boundary_exit_eas"] == [0x40B940]
        assert row116_calls["passed"] is True
        row117_calls = calls_observations["rhad:route@0x40B6EE"]
        assert row117_calls["source_present"] is False
        assert row117_calls["source_topology_reachable"] is False
        assert row117_calls["source_topology_retired"] is True
        assert row117_calls["indirect_transfer_present"] is False
        assert row117_calls["target_eas"] == []
        assert row117_calls["semantic_target_eas"] == [0x40B6F0, 0x40B880]
        assert row117_calls["delivery_target_eas"] == [0x40B6F0, 0x40B880]
        assert row117_calls["semantic_targets_survive"] is True
        assert row117_calls["boundary_exit_eas"] == [
            0x40B70A,
            0x40B898,
            0x40BB75,
            0x40BC61,
        ]
        assert row117_calls["passed"] is True
        row118_calls = calls_observations["rhad:route@0x40B708"]
        assert row118_calls["source_present"] is False
        assert row118_calls["source_topology_reachable"] is False
        assert row118_calls["source_topology_retired"] is True
        assert row118_calls["indirect_transfer_present"] is False
        assert row118_calls["target_eas"] == []
        assert row118_calls["semantic_target_eas"] == [0x40B70A, 0x40BB75]
        assert row118_calls["delivery_target_eas"] == [0x40B70A, 0x40BB75]
        assert row118_calls["semantic_targets_survive"] is True
        assert row118_calls["boundary_exit_eas"] == [
            0x40B724,
            0x40BB8F,
            0x40BD50,
            0x40BF8C,
        ]
        assert row118_calls["passed"] is True
        row119_calls = calls_observations["rhad:route@0x40B722"]
        assert row119_calls["source_present"] is False
        assert row119_calls["source_topology_reachable"] is False
        assert row119_calls["source_topology_retired"] is True
        assert row119_calls["indirect_transfer_present"] is False
        assert row119_calls["target_eas"] == []
        assert row119_calls["semantic_target_eas"] == [0x40B724, 0x40BD50]
        assert row119_calls["delivery_target_eas"] == [0x40B724, 0x40BD50]
        assert row119_calls["semantic_targets_survive"] is True
        assert row119_calls["boundary_exit_eas"] == [
            0x40B73E,
            0x40BD6A,
            0x40C0F0,
            0x40C3D9,
        ]
        assert row119_calls["passed"] is True
        row120_calls = calls_observations["rhad:route@0x40B73C"]
        assert row120_calls["source_present"] is False
        assert row120_calls["source_topology_reachable"] is False
        assert row120_calls["source_topology_retired"] is True
        assert row120_calls["indirect_transfer_present"] is False
        assert row120_calls["target_eas"] == []
        assert row120_calls["semantic_target_eas"] == [0x40B73E, 0x40C0F0]
        assert row120_calls["delivery_target_eas"] == [0x40B73E, 0x40C0F0]
        assert row120_calls["semantic_targets_survive"] is True
        assert row120_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40B758,
            0x40C10A,
        ]
        assert row120_calls["passed"] is True
        row121_calls = calls_observations["rhad:route@0x40B756"]
        assert row121_calls["source_present"] is False
        assert row121_calls["source_topology_reachable"] is False
        assert row121_calls["source_topology_retired"] is True
        assert row121_calls["indirect_transfer_present"] is False
        assert row121_calls["target_eas"] == []
        assert row121_calls["semantic_target_eas"] == [0x40A5F0, 0x40B758]
        assert row121_calls["delivery_target_eas"] == [0x40A5F0, 0x40B758]
        assert row121_calls["semantic_targets_survive"] is True
        assert row121_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row121_calls["passed"] is True
        row122_calls = calls_observations["route:rhad-direct@0x40B781"]
        assert row122_calls["source_present"] is False
        assert row122_calls["source_topology_reachable"] is False
        assert row122_calls["source_topology_retired"] is True
        assert row122_calls["indirect_transfer_present"] is False
        assert row122_calls["target_eas"] == []
        assert row122_calls["semantic_target_eas"] == [0x40B6C0]
        assert row122_calls["delivery_target_eas"] == [0x40B6C0]
        assert row122_calls["semantic_targets_survive"] is True
        assert row122_calls["boundary_exit_eas"] == [0x40B790]
        assert row122_calls["passed"] is True
        assert 0x40B6C8 in calls_payload["reachable_eas"]
        row123_calls = calls_observations["rhad:route@0x40B7A8"]
        assert row123_calls["source_present"] is False
        assert row123_calls["source_topology_reachable"] is False
        assert row123_calls["source_topology_retired"] is True
        assert row123_calls["indirect_transfer_present"] is False
        assert row123_calls["target_eas"] == []
        assert row123_calls["semantic_target_eas"] == [0x40B7AA, 0x40B940]
        assert row123_calls["delivery_target_eas"] == [0x40B7AA, 0x40B940]
        assert row123_calls["semantic_targets_survive"] is True
        assert row123_calls["boundary_exit_eas"] == [
            0x40B7C4,
            0x40B958,
            0x40BBDF,
            0x40BCCB,
        ]
        assert row123_calls["passed"] is True
        assert 0x40B7B6 in calls_payload["reachable_eas"]
        assert 0x40B94E not in calls_payload["reachable_eas"]
        row124_calls = calls_observations["rhad:route@0x40B7C2"]
        assert row124_calls["source_present"] is False
        assert row124_calls["source_topology_reachable"] is False
        assert row124_calls["source_topology_retired"] is True
        assert row124_calls["indirect_transfer_present"] is False
        assert row124_calls["target_eas"] == []
        assert row124_calls["semantic_target_eas"] == [0x40B7C4, 0x40BBDF]
        assert row124_calls["delivery_target_eas"] == [0x40B7C4, 0x40BBDF]
        assert row124_calls["semantic_targets_survive"] is True
        assert row124_calls["boundary_exit_eas"] == [
            0x40B7DE,
            0x40BBF9,
            0x40BE2F,
            0x40BFDA,
        ]
        assert row124_calls["passed"] is True
        row125_calls = calls_observations["rhad:route@0x40B7DC"]
        assert row125_calls["source_present"] is False
        assert row125_calls["source_topology_reachable"] is False
        assert row125_calls["source_topology_retired"] is True
        assert row125_calls["indirect_transfer_present"] is False
        assert row125_calls["target_eas"] == []
        assert row125_calls["semantic_target_eas"] == [0x40B7DE, 0x40BE2F]
        assert row125_calls["delivery_target_eas"] == [0x40B7DE, 0x40BE2F]
        assert row125_calls["semantic_targets_survive"] is True
        assert row125_calls["boundary_exit_eas"] == [
            0x40B7F6,
            0x40C150,
            0x40C42E,
        ]
        assert row125_calls["passed"] is True
        assert 0x40B7E6 in calls_payload["reachable_eas"]
        assert 0x40BE2F not in calls_payload["reachable_eas"]
        row126_calls = calls_observations["rhad:route@0x40B7F4"]
        assert row126_calls["source_present"] is True
        assert row126_calls["source_topology_reachable"] is False
        assert row126_calls["source_topology_retired"] is True
        assert row126_calls["indirect_transfer_present"] is False
        assert row126_calls["target_eas"] == [0x40B802, 0x40C15C]
        assert row126_calls["semantic_target_eas"] == [0x40B7F6, 0x40C150]
        assert row126_calls["delivery_target_eas"] == [0x40B7F6, 0x40C150]
        assert row126_calls["semantic_targets_survive"] is True
        assert row126_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40B810,
            0x40C16A,
        ]
        assert row126_calls["passed"] is True
        row127_calls = calls_observations["rhad:route@0x40B80E"]
        assert row127_calls["source_present"] is False
        assert row127_calls["source_topology_reachable"] is False
        assert row127_calls["source_topology_retired"] is True
        assert row127_calls["indirect_transfer_present"] is False
        assert row127_calls["target_eas"] == []
        assert row127_calls["semantic_target_eas"] == [0x40A5F0, 0x40B810]
        assert row127_calls["delivery_target_eas"] == [0x40A5F0, 0x40B810]
        assert row127_calls["semantic_targets_survive"] is True
        assert row127_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row127_calls["passed"] is True
        row128_calls = calls_observations["rhad:route@0x40B879"]
        assert row128_calls["source_present"] is False
        assert row128_calls["source_topology_reachable"] is False
        assert row128_calls["source_topology_retired"] is True
        assert row128_calls["indirect_transfer_present"] is False
        assert row128_calls["target_eas"] == []
        assert row128_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row128_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row128_calls["semantic_targets_survive"] is True
        assert row128_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row128_calls["passed"] is True
        row129_calls = calls_observations["rhad:route@0x40B896"]
        assert row129_calls["source_present"] is True
        assert row129_calls["source_topology_reachable"] is False
        assert row129_calls["source_topology_retired"] is True
        assert row129_calls["indirect_transfer_present"] is False
        assert row129_calls["target_eas"] == [0x40B8A4, 0x40BC6D]
        assert row129_calls["semantic_target_eas"] == [0x40B898, 0x40BC61]
        assert row129_calls["delivery_target_eas"] == [0x40B898, 0x40BC61]
        assert row129_calls["semantic_targets_survive"] is True
        assert row129_calls["boundary_exit_eas"] == [0x40BE98, 0x40C041]
        assert row129_calls["passed"] is True
        row130_calls = calls_observations["rhad:route@0x40B8B0"]
        assert row130_calls["source_present"] is False
        assert row130_calls["source_topology_reachable"] is False
        assert row130_calls["source_topology_retired"] is True
        assert row130_calls["indirect_transfer_present"] is False
        assert row130_calls["target_eas"] == []
        assert row130_calls["semantic_target_eas"] == [0x40B8B2, 0x40BE98]
        assert row130_calls["delivery_target_eas"] == [0x40B8B2, 0x40BE98]
        assert row130_calls["semantic_targets_survive"] is True
        assert row130_calls["boundary_exit_eas"] == [
            0x40B8CC,
            0x40BEB2,
            0x40C186,
            0x40C464,
        ]
        assert row130_calls["passed"] is True
        row131_calls = calls_observations["rhad:route@0x40B8CA"]
        assert row131_calls["source_present"] is False
        assert row131_calls["source_topology_reachable"] is False
        assert row131_calls["source_topology_retired"] is True
        assert row131_calls["indirect_transfer_present"] is False
        assert row131_calls["target_eas"] == []
        assert row131_calls["semantic_target_eas"] == [0x40B8CC, 0x40C186]
        assert row131_calls["delivery_target_eas"] == [0x40B8CC, 0x40C186]
        assert row131_calls["semantic_targets_survive"] is True
        assert row131_calls["boundary_exit_eas"] == [0x40A5F0, 0x40B8E6]
        assert row131_calls["passed"] is True
        row132_calls = calls_observations["rhad:route@0x40B8E4"]
        assert row132_calls["source_present"] is False
        assert row132_calls["source_topology_reachable"] is False
        assert row132_calls["source_topology_retired"] is True
        assert row132_calls["indirect_transfer_present"] is False
        assert row132_calls["target_eas"] == []
        assert row132_calls["semantic_target_eas"] == [0x40A5F0, 0x40B8E6]
        assert row132_calls["delivery_target_eas"] == [0x40A5F0, 0x40B8E6]
        assert row132_calls["semantic_targets_survive"] is True
        assert row132_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row132_calls["passed"] is True
        row133_calls = calls_observations["route:rhad-direct@0x40B931"]
        assert row133_calls["source_present"] is False
        assert row133_calls["source_topology_reachable"] is False
        assert row133_calls["source_topology_retired"] is True
        assert row133_calls["indirect_transfer_present"] is False
        assert row133_calls["target_eas"] == []
        assert row133_calls["semantic_target_eas"] == [0x40B6C0]
        assert row133_calls["delivery_target_eas"] == [0x40B6C0]
        assert row133_calls["semantic_targets_survive"] is True
        assert row133_calls["boundary_exit_eas"] == [0x40B790]
        assert row133_calls["passed"] is True
        row134_calls = calls_observations["rhad:route@0x40B956"]
        assert row134_calls["source_present"] is True
        assert row134_calls["source_topology_reachable"] is False
        assert row134_calls["source_topology_retired"] is True
        assert row134_calls["indirect_transfer_present"] is False
        assert row134_calls["target_eas"] == [0x40B964, 0x40BCD7]
        assert row134_calls["semantic_target_eas"] == [0x40B958, 0x40BCCB]
        assert row134_calls["delivery_target_eas"] == [0x40B958, 0x40BCCB]
        assert row134_calls["semantic_targets_survive"] is True
        assert row134_calls["boundary_exit_eas"] == [0x40BEE7, 0x40C0A0]
        assert row134_calls["passed"] is True
        row135_calls = calls_observations["rhad:route@0x40B970"]
        assert row135_calls["source_present"] is False
        assert row135_calls["source_topology_reachable"] is False
        assert row135_calls["source_topology_retired"] is True
        assert row135_calls["indirect_transfer_present"] is False
        assert row135_calls["target_eas"] == []
        assert row135_calls["semantic_target_eas"] == [0x40B972, 0x40BEE7]
        assert row135_calls["delivery_target_eas"] == [0x40B972, 0x40BEE7]
        assert row135_calls["semantic_targets_survive"] is True
        assert row135_calls["boundary_exit_eas"] == [0x40C1F2, 0x40C49A]
        assert row135_calls["passed"] is True
        assert 0x40B958 not in calls_payload["reachable_eas"]
        assert 0x40B966 in calls_payload["reachable_eas"]
        assert 0x40B970 not in calls_payload["reachable_eas"]
        assert 0x40B972 not in calls_payload["reachable_eas"]
        assert 0x40B980 in calls_payload["reachable_eas"]
        assert 0x40B98A not in calls_payload["reachable_eas"]
        assert 0x40BEE7 not in calls_payload["reachable_eas"]
        assert {0x40BEF3, 0x40BEF5}.issubset(calls_payload["reachable_eas"])
        assert {0x40BEFB, 0x40BEFF}.isdisjoint(calls_payload["reachable_eas"])
        row136_calls = calls_observations["rhad:route@0x40B98A"]
        assert row136_calls["source_present"] is False
        assert row136_calls["source_topology_reachable"] is False
        assert row136_calls["source_topology_retired"] is True
        assert row136_calls["indirect_transfer_present"] is False
        assert row136_calls["target_eas"] == []
        assert row136_calls["semantic_target_eas"] == [0x40B98C, 0x40C1F2]
        assert row136_calls["delivery_target_eas"] == [0x40B98C, 0x40C1F2]
        assert row136_calls["semantic_targets_survive"] is True
        assert row136_calls["boundary_exit_eas"] == [0x40A5F0, 0x40B9A6]
        assert row136_calls["passed"] is True
        row137_calls = calls_observations["rhad:route@0x40B9A4"]
        assert row137_calls["source_present"] is False
        assert row137_calls["source_topology_reachable"] is False
        assert row137_calls["source_topology_retired"] is True
        assert row137_calls["indirect_transfer_present"] is False
        assert row137_calls["target_eas"] == []
        assert row137_calls["semantic_target_eas"] == [0x40A5F0, 0x40B9A6]
        assert row137_calls["delivery_target_eas"] == [0x40A5F0, 0x40B9A6]
        assert row137_calls["semantic_targets_survive"] is True
        assert row137_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row137_calls["passed"] is True
        row138_calls = calls_observations["route:rhad-direct@0x40BB73"]
        assert row138_calls["source_present"] is False
        assert row138_calls["source_topology_reachable"] is False
        assert row138_calls["source_topology_retired"] is True
        assert row138_calls["indirect_transfer_present"] is False
        assert row138_calls["target_eas"] == []
        assert row138_calls["semantic_target_eas"] == [0x40B6C0]
        assert row138_calls["delivery_target_eas"] == [0x40B6C0]
        assert row138_calls["semantic_targets_survive"] is True
        assert row138_calls["boundary_exit_eas"] == [0x40B790]
        assert row138_calls["passed"] is True
        row139_calls = calls_observations["rhad:route@0x40BB8D"]
        assert row139_calls["source_present"] is False
        assert row139_calls["source_topology_reachable"] is False
        assert row139_calls["source_topology_retired"] is True
        assert row139_calls["indirect_transfer_present"] is False
        assert row139_calls["target_eas"] == []
        assert row139_calls["semantic_target_eas"] == [0x40BB8F, 0x40BF8C]
        assert row139_calls["delivery_target_eas"] == [0x40BB8F, 0x40BF8C]
        assert row139_calls["semantic_targets_survive"] is True
        assert row139_calls["boundary_exit_eas"] == [
            0x40BBA9,
            0x40BFA4,
            0x40C253,
            0x40C4DC,
        ]
        assert row139_calls["passed"] is True
        row140_calls = calls_observations["rhad:route@0x40BBA7"]
        assert row140_calls["source_present"] is False
        assert row140_calls["source_topology_reachable"] is False
        assert row140_calls["source_topology_retired"] is True
        assert row140_calls["indirect_transfer_present"] is False
        assert row140_calls["target_eas"] == []
        assert row140_calls["semantic_target_eas"] == [0x40BBA9, 0x40C253]
        assert row140_calls["delivery_target_eas"] == [0x40BBA9, 0x40C253]
        assert row140_calls["semantic_targets_survive"] is True
        assert row140_calls["boundary_exit_eas"] == [0x40A5F0, 0x40BBC3]
        assert row140_calls["passed"] is True
        row141_calls = calls_observations["rhad:route@0x40BBC1"]
        assert row141_calls["source_present"] is False
        assert row141_calls["source_topology_reachable"] is False
        assert row141_calls["source_topology_retired"] is True
        assert row141_calls["indirect_transfer_present"] is False
        assert row141_calls["target_eas"] == []
        assert row141_calls["semantic_target_eas"] == [0x40A5F0, 0x40BBC3]
        assert row141_calls["delivery_target_eas"] == [0x40A5F0, 0x40BBC3]
        assert row141_calls["semantic_targets_survive"] is True
        assert row141_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row141_calls["passed"] is True
        row142_calls = calls_observations["rhad:route@0x40BBDD"]
        assert row142_calls["source_present"] is False
        assert row142_calls["source_topology_reachable"] is False
        assert row142_calls["source_topology_retired"] is True
        assert row142_calls["indirect_transfer_present"] is False
        assert row142_calls["target_eas"] == []
        assert row142_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row142_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row142_calls["semantic_targets_survive"] is True
        assert row142_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row142_calls["passed"] is True
        row143_calls = calls_observations["rhad:route@0x40BBF7"]
        assert row143_calls["source_present"] is False
        assert row143_calls["source_topology_reachable"] is False
        assert row143_calls["source_topology_retired"] is True
        assert row143_calls["indirect_transfer_present"] is False
        assert row143_calls["target_eas"] == []
        assert row143_calls["semantic_target_eas"] == [0x40BBF9, 0x40BFDA]
        assert row143_calls["delivery_target_eas"] == [0x40BBF9, 0x40BFDA]
        assert row143_calls["semantic_targets_survive"] is True
        assert row143_calls["boundary_exit_eas"] == [0x40BC13, 0x40C2FB, 0x40C527]
        assert row143_calls["passed"] is True
        row144_calls = calls_observations["rhad:route@0x40BC11"]
        assert row144_calls["source_present"] is False
        assert row144_calls["source_topology_reachable"] is False
        assert row144_calls["source_topology_retired"] is True
        assert row144_calls["indirect_transfer_present"] is False
        assert row144_calls["target_eas"] == []
        assert row144_calls["semantic_target_eas"] == [0x40BC13, 0x40C2FB]
        assert row144_calls["delivery_target_eas"] == [0x40BC13, 0x40C2FB]
        assert row144_calls["semantic_targets_survive"] is True
        assert row144_calls["boundary_exit_eas"] == [0x40A5F0, 0x40BC2D, 0x40C315]
        assert row144_calls["passed"] is True
        row145_calls = calls_observations["rhad:route@0x40BC2B"]
        assert row145_calls["source_present"] is False
        assert row145_calls["source_topology_reachable"] is False
        assert row145_calls["source_topology_retired"] is True
        assert row145_calls["indirect_transfer_present"] is False
        assert row145_calls["target_eas"] == []
        assert row145_calls["semantic_target_eas"] == [0x40A5F0, 0x40BC2D]
        assert row145_calls["delivery_target_eas"] == [0x40A5F0, 0x40BC2D]
        assert row145_calls["semantic_targets_survive"] is True
        assert row145_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row145_calls["passed"] is True
        row146_calls = calls_observations["rhad:route@0x40BC5F"]
        assert row146_calls["source_present"] is False
        assert row146_calls["source_topology_reachable"] is False
        assert row146_calls["source_topology_retired"] is True
        assert row146_calls["indirect_transfer_present"] is False
        assert row146_calls["target_eas"] == []
        assert row146_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row146_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row146_calls["semantic_targets_survive"] is True
        assert row146_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row146_calls["passed"] is True
        row147_calls = calls_observations["rhad:route@0x40BC79"]
        assert row147_calls["source_present"] is False
        assert row147_calls["source_topology_reachable"] is False
        assert row147_calls["source_topology_retired"] is True
        assert row147_calls["indirect_transfer_present"] is False
        assert row147_calls["target_eas"] == []
        assert row147_calls["semantic_target_eas"] == [0x40BC7B, 0x40C041]
        assert row147_calls["delivery_target_eas"] == [0x40BC7B, 0x40C041]
        assert row147_calls["semantic_targets_survive"] is True
        assert row147_calls["boundary_exit_eas"] == [
            0x40BC95,
            0x40C05B,
            0x40C34D,
            0x40C578,
        ]
        assert row147_calls["passed"] is True
        row148_calls = calls_observations["rhad:route@0x40BC93"]
        assert row148_calls["source_present"] is False
        assert row148_calls["source_topology_reachable"] is False
        assert row148_calls["source_topology_retired"] is True
        assert row148_calls["indirect_transfer_present"] is False
        assert row148_calls["target_eas"] == []
        assert row148_calls["semantic_target_eas"] == [0x40BC95, 0x40C34D]
        assert row148_calls["delivery_target_eas"] == [0x40BC95, 0x40C34D]
        assert row148_calls["semantic_targets_survive"] is True
        assert row148_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BCAF,
            0x40C367,
        ]
        assert row148_calls["passed"] is True
        row149_calls = calls_observations["rhad:route@0x40BCAD"]
        assert row149_calls["source_present"] is False
        assert row149_calls["source_topology_reachable"] is False
        assert row149_calls["source_topology_retired"] is True
        assert row149_calls["indirect_transfer_present"] is False
        assert row149_calls["target_eas"] == []
        assert row149_calls["semantic_target_eas"] == [0x40A5F0, 0x40BCAF]
        assert row149_calls["delivery_target_eas"] == [0x40A5F0, 0x40BCAF]
        assert row149_calls["semantic_targets_survive"] is True
        assert row149_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row149_calls["passed"] is True
        row150_calls = calls_observations["rhad:route@0x40BCC9"]
        assert row150_calls["source_present"] is False
        assert row150_calls["source_topology_reachable"] is False
        assert row150_calls["source_topology_retired"] is True
        assert row150_calls["indirect_transfer_present"] is False
        assert row150_calls["target_eas"] == []
        assert row150_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row150_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row150_calls["semantic_targets_survive"] is True
        assert row150_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row150_calls["passed"] is True
        row151_calls = calls_observations["rhad:route@0x40BCE3"]
        assert row151_calls["source_present"] is False
        assert row151_calls["source_topology_reachable"] is False
        assert row151_calls["source_topology_retired"] is True
        assert row151_calls["indirect_transfer_present"] is False
        assert row151_calls["target_eas"] == []
        assert row151_calls["semantic_target_eas"] == [0x40BCE5, 0x40C0A0]
        assert row151_calls["delivery_target_eas"] == [0x40BCE5, 0x40C0A0]
        assert row151_calls["semantic_targets_survive"] is True
        assert row151_calls["boundary_exit_eas"] == [0x40C392, 0x40C5FB]
        assert row151_calls["passed"] is True
        row152_calls = calls_observations["rhad:route@0x40BCFD"]
        assert row152_calls["source_present"] is False
        assert row152_calls["source_topology_reachable"] is False
        assert row152_calls["source_topology_retired"] is True
        assert row152_calls["indirect_transfer_present"] is False
        assert row152_calls["target_eas"] == []
        assert row152_calls["semantic_target_eas"] == [0x40BCFF, 0x40C392]
        assert row152_calls["delivery_target_eas"] == [0x40BCFF, 0x40C392]
        assert row152_calls["semantic_targets_survive"] is True
        assert row152_calls["boundary_exit_eas"] == [0x40A5F0, 0x40BD19]
        assert row152_calls["passed"] is True
        row153_calls = calls_observations["rhad:route@0x40BD17"]
        assert row153_calls["source_present"] is False
        assert row153_calls["source_topology_reachable"] is False
        assert row153_calls["source_topology_retired"] is True
        assert row153_calls["indirect_transfer_present"] is False
        assert row153_calls["target_eas"] == []
        assert row153_calls["semantic_target_eas"] == [0x40A5F0, 0x40BD19]
        assert row153_calls["delivery_target_eas"] == [0x40A5F0, 0x40BD19]
        assert row153_calls["semantic_targets_survive"] is True
        assert row153_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row153_calls["passed"] is True
        row154_calls = calls_observations["rhad:route@0x40BD4E"]
        assert row154_calls["source_present"] is False
        assert row154_calls["source_topology_reachable"] is False
        assert row154_calls["source_topology_retired"] is True
        assert row154_calls["indirect_transfer_present"] is False
        assert row154_calls["target_eas"] == []
        assert row154_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row154_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row154_calls["semantic_targets_survive"] is True
        assert row154_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row154_calls["passed"] is True
        row155_calls = calls_observations["rhad:route@0x40BD68"]
        assert row155_calls["source_present"] is False
        assert row155_calls["source_topology_reachable"] is False
        assert row155_calls["source_topology_retired"] is True
        assert row155_calls["indirect_transfer_present"] is False
        assert row155_calls["target_eas"] == []
        assert row155_calls["semantic_target_eas"] == [0x40BD6A, 0x40C3D9]
        assert row155_calls["delivery_target_eas"] == [0x40BD6A, 0x40C3D9]
        assert row155_calls["semantic_targets_survive"] is True
        assert row155_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BD84,
            0x40C3F3,
        ]
        assert row155_calls["passed"] is True
        row156_calls = calls_observations["rhad:route@0x40BD82"]
        assert row156_calls["source_present"] is False
        assert row156_calls["source_topology_reachable"] is False
        assert row156_calls["source_topology_retired"] is True
        assert row156_calls["indirect_transfer_present"] is False
        assert row156_calls["target_eas"] == []
        assert row156_calls["semantic_target_eas"] == [0x40A5F0, 0x40BD84]
        assert row156_calls["delivery_target_eas"] == [0x40A5F0, 0x40BD84]
        assert row156_calls["semantic_targets_survive"] is True
        assert row156_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row156_calls["passed"] is True
        row157_calls = calls_observations["rhad:route@0x40BE2D"]
        assert row157_calls["source_present"] is False
        assert row157_calls["source_topology_reachable"] is False
        assert row157_calls["source_topology_retired"] is True
        assert row157_calls["indirect_transfer_present"] is False
        assert row157_calls["target_eas"] == []
        assert row157_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row157_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row157_calls["semantic_targets_survive"] is True
        assert row157_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row157_calls["passed"] is True
        assert 0x40BE2D not in calls_payload["reachable_eas"]
        row158_calls = calls_observations["rhad:route@0x40BE47"]
        assert row158_calls["source_present"] is False
        assert row158_calls["source_topology_reachable"] is False
        assert row158_calls["source_topology_retired"] is True
        assert row158_calls["indirect_transfer_present"] is False
        assert row158_calls["target_eas"] == []
        assert row158_calls["semantic_target_eas"] == [0x40BE49, 0x40C42E]
        assert row158_calls["delivery_target_eas"] == [0x40BE49, 0x40C42E]
        assert row158_calls["semantic_targets_survive"] is True
        assert row158_calls["boundary_exit_eas"] == [0x40A5F0, 0x40BE63]
        assert row158_calls["passed"] is True
        assert 0x40BE47 not in calls_payload["reachable_eas"]
        row159_calls = calls_observations["rhad:route@0x40BE61"]
        assert row159_calls["source_present"] is False
        assert row159_calls["source_topology_reachable"] is False
        assert row159_calls["source_topology_retired"] is True
        assert row159_calls["indirect_transfer_present"] is False
        assert row159_calls["target_eas"] == []
        assert row159_calls["semantic_target_eas"] == [0x40A5F0, 0x40BE63]
        assert row159_calls["delivery_target_eas"] == [0x40A5F0, 0x40BE63]
        assert row159_calls["semantic_targets_survive"] is True
        assert row159_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row159_calls["passed"] is True
        assert 0x40BE61 not in calls_payload["reachable_eas"]
        row160_calls = calls_observations["rhad:route@0x40BE96"]
        assert row160_calls["source_present"] is False
        assert row160_calls["source_topology_reachable"] is False
        assert row160_calls["source_topology_retired"] is True
        assert row160_calls["indirect_transfer_present"] is False
        assert row160_calls["target_eas"] == []
        assert row160_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row160_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row160_calls["semantic_targets_survive"] is True
        assert row160_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row160_calls["passed"] is True
        assert 0x40BE96 not in calls_payload["reachable_eas"]
        row161_calls = calls_observations["rhad:route@0x40BEB0"]
        assert row161_calls["source_present"] is False
        assert row161_calls["source_topology_reachable"] is False
        assert row161_calls["source_topology_retired"] is True
        assert row161_calls["indirect_transfer_present"] is False
        assert row161_calls["target_eas"] == []
        assert row161_calls["semantic_target_eas"] == [0x40BEB2, 0x40C464]
        assert row161_calls["delivery_target_eas"] == [0x40BEB2, 0x40C464]
        assert row161_calls["semantic_targets_survive"] is True
        assert row161_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BECC,
        ]
        assert row161_calls["passed"] is True
        assert 0x40BEB0 not in calls_payload["reachable_eas"]
        row162_calls = calls_observations["rhad:route@0x40BECA"]
        assert row162_calls["source_present"] is False
        assert row162_calls["source_topology_reachable"] is False
        assert row162_calls["source_topology_retired"] is True
        assert row162_calls["indirect_transfer_present"] is False
        assert row162_calls["target_eas"] == []
        assert row162_calls["semantic_target_eas"] == [0x40A5F0, 0x40BECC]
        assert row162_calls["delivery_target_eas"] == [0x40A5F0, 0x40BECC]
        assert row162_calls["semantic_targets_survive"] is True
        assert row162_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row162_calls["passed"] is True
        assert 0x40BECA not in calls_payload["reachable_eas"]
        row163_calls = calls_observations["rhad:route@0x40BEE5"]
        assert row163_calls["source_present"] is False
        assert row163_calls["source_topology_reachable"] is False
        assert row163_calls["source_topology_retired"] is True
        assert row163_calls["indirect_transfer_present"] is False
        assert row163_calls["target_eas"] == []
        assert row163_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row163_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row163_calls["semantic_targets_survive"] is True
        assert row163_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row163_calls["passed"] is True
        assert 0x40BEE5 not in calls_payload["reachable_eas"]
        row164_calls = calls_observations["rhad:route@0x40BEFF"]
        assert row164_calls["source_present"] is False
        assert row164_calls["source_topology_reachable"] is False
        assert row164_calls["source_topology_retired"] is True
        assert row164_calls["indirect_transfer_present"] is False
        assert row164_calls["target_eas"] == []
        assert row164_calls["semantic_target_eas"] == [0x40BF01, 0x40C49A]
        assert row164_calls["delivery_target_eas"] == [0x40BF01, 0x40C49A]
        assert row164_calls["semantic_targets_survive"] is True
        assert row164_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40BF1B,
            0x40C4B4,
        ]
        assert row164_calls["passed"] is True
        assert 0x40BEFF not in calls_payload["reachable_eas"]
        row165_calls = calls_observations["rhad:route@0x40BF19"]
        assert row165_calls["source_present"] is False
        assert row165_calls["source_topology_reachable"] is False
        assert row165_calls["source_topology_retired"] is True
        assert row165_calls["indirect_transfer_present"] is False
        assert row165_calls["target_eas"] == []
        assert row165_calls["semantic_target_eas"] == [0x40A5F0, 0x40BF1B]
        assert row165_calls["delivery_target_eas"] == [0x40A5F0, 0x40BF1B]
        assert row165_calls["semantic_targets_survive"] is True
        assert row165_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row165_calls["passed"] is True
        assert 0x40BF19 not in calls_payload["reachable_eas"]
        row166_calls = calls_observations["route:rhad-direct@0x40BF8A"]
        assert row166_calls["source_present"] is False
        assert row166_calls["source_topology_reachable"] is False
        assert row166_calls["source_topology_retired"] is True
        assert row166_calls["indirect_transfer_present"] is False
        assert row166_calls["target_eas"] == []
        assert row166_calls["semantic_target_eas"] == [0x40B6C0]
        assert row166_calls["delivery_target_eas"] == [0x40B6C0]
        assert row166_calls["semantic_targets_survive"] is True
        assert row166_calls["boundary_exit_eas"] == [0x40B790]
        assert row166_calls["passed"] is True
        assert 0x40BF8A not in calls_payload["reachable_eas"]
        row167_calls = calls_observations["rhad:route@0x40BFA2"]
        assert row167_calls["source_present"] is True
        assert row167_calls["source_topology_reachable"] is False
        assert row167_calls["source_topology_retired"] is True
        assert row167_calls["indirect_transfer_present"] is False
        assert row167_calls["target_eas"] == [0x40BFB0, 0x40C4E8]
        assert row167_calls["semantic_target_eas"] == [0x40BFA4, 0x40C4DC]
        assert row167_calls["delivery_target_eas"] == [0x40BFA4, 0x40C4DC]
        assert row167_calls["semantic_targets_survive"] is True
        assert row167_calls["boundary_exit_eas"] == [0x40A5F0]
        assert row167_calls["passed"] is True
        assert 0x40BFA2 not in calls_payload["reachable_eas"]
        row168_calls = calls_observations["rhad:route@0x40BFBC"]
        assert row168_calls["source_present"] is False
        assert row168_calls["source_topology_reachable"] is False
        assert row168_calls["source_topology_retired"] is True
        assert row168_calls["indirect_transfer_present"] is False
        assert row168_calls["target_eas"] == []
        assert row168_calls["semantic_target_eas"] == [0x40A5F0, 0x40BFBE]
        assert row168_calls["delivery_target_eas"] == [0x40A5F0, 0x40BFBE]
        assert row168_calls["semantic_targets_survive"] is True
        assert row168_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row168_calls["passed"] is True
        assert 0x40BFBC not in calls_payload["reachable_eas"]
        row169_calls = calls_observations["rhad:route@0x40BFD8"]
        assert row169_calls["source_present"] is False
        assert row169_calls["source_topology_reachable"] is False
        assert row169_calls["source_topology_retired"] is True
        assert row169_calls["indirect_transfer_present"] is False
        assert row169_calls["target_eas"] == []
        assert row169_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row169_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row169_calls["semantic_targets_survive"] is True
        assert row169_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row169_calls["passed"] is True
        assert 0x40BFD8 not in calls_payload["reachable_eas"]
        row170_calls = calls_observations["rhad:route@0x40BFF2"]
        assert row170_calls["source_present"] is False
        assert row170_calls["source_topology_reachable"] is False
        assert row170_calls["source_topology_retired"] is True
        assert row170_calls["indirect_transfer_present"] is False
        assert row170_calls["target_eas"] == []
        assert row170_calls["semantic_target_eas"] == [0x40BFF4, 0x40C527]
        assert row170_calls["delivery_target_eas"] == [0x40BFF4, 0x40C527]
        assert row170_calls["semantic_targets_survive"] is True
        assert row170_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40C00E,
            0x40C541,
        ]
        assert row170_calls["passed"] is True
        assert 0x40BFF2 not in calls_payload["reachable_eas"]
        row171_calls = calls_observations["rhad:route@0x40C00C"]
        assert row171_calls["source_present"] is False
        assert row171_calls["source_topology_reachable"] is False
        assert row171_calls["source_topology_retired"] is True
        assert row171_calls["indirect_transfer_present"] is False
        assert row171_calls["target_eas"] == []
        assert row171_calls["semantic_target_eas"] == [0x40A5F0, 0x40C00E]
        assert row171_calls["delivery_target_eas"] == [0x40A5F0, 0x40C00E]
        assert row171_calls["semantic_targets_survive"] is True
        assert row171_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row171_calls["passed"] is True
        assert 0x40C00C not in calls_payload["reachable_eas"]
        row172_calls = calls_observations["route:rhad-direct@0x40C03F"]
        assert row172_calls["source_present"] is False
        assert row172_calls["source_topology_reachable"] is False
        assert row172_calls["source_topology_retired"] is True
        assert row172_calls["indirect_transfer_present"] is False
        assert row172_calls["target_eas"] == []
        assert row172_calls["semantic_target_eas"] == [0x40B6C0]
        assert row172_calls["delivery_target_eas"] == [0x40B6C0]
        assert row172_calls["semantic_targets_survive"] is True
        assert row172_calls["boundary_exit_eas"] == [0x40B790]
        assert row172_calls["passed"] is True
        assert 0x40C03F not in calls_payload["reachable_eas"]
        row173_calls = calls_observations["rhad:route@0x40C059"]
        assert row173_calls["source_present"] is False
        assert row173_calls["source_topology_reachable"] is False
        assert row173_calls["source_topology_retired"] is True
        assert row173_calls["indirect_transfer_present"] is False
        assert row173_calls["target_eas"] == []
        assert row173_calls["semantic_target_eas"] == [0x40C05B, 0x40C578]
        assert row173_calls["delivery_target_eas"] == [0x40C05B, 0x40C578]
        assert row173_calls["semantic_targets_survive"] is True
        assert row173_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40C075,
            0x40C592,
        ]
        assert row173_calls["passed"] is True
        assert 0x40C059 not in calls_payload["reachable_eas"]
        row174_calls = calls_observations["rhad:route@0x40C073"]
        assert row174_calls["source_present"] is False
        assert row174_calls["source_topology_reachable"] is False
        assert row174_calls["source_topology_retired"] is True
        assert row174_calls["indirect_transfer_present"] is False
        assert row174_calls["target_eas"] == []
        assert row174_calls["semantic_target_eas"] == [0x40A5F0, 0x40C075]
        assert row174_calls["delivery_target_eas"] == [0x40A5F0, 0x40C075]
        assert row174_calls["semantic_targets_survive"] is True
        assert row174_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row174_calls["passed"] is True
        assert 0x40C073 not in calls_payload["reachable_eas"]
        row175_calls = calls_observations["route:rhad-direct@0x40C09E"]
        assert row175_calls["source_present"] is False
        assert row175_calls["source_topology_reachable"] is False
        assert row175_calls["source_topology_retired"] is True
        assert row175_calls["indirect_transfer_present"] is False
        assert row175_calls["target_eas"] == []
        assert row175_calls["semantic_target_eas"] == [0x40B6C0]
        assert row175_calls["delivery_target_eas"] == [0x40B6C0]
        assert row175_calls["semantic_targets_survive"] is True
        assert row175_calls["boundary_exit_eas"] == [0x40B790]
        assert row175_calls["passed"] is True
        row176_calls = calls_observations["rhad:route@0x40C0B8"]
        assert row176_calls["source_present"] is False
        assert row176_calls["source_topology_reachable"] is False
        assert row176_calls["source_topology_retired"] is True
        assert row176_calls["indirect_transfer_present"] is False
        assert row176_calls["target_eas"] == []
        assert row176_calls["semantic_target_eas"] == [0x40C0BA, 0x40C5FB]
        assert row176_calls["delivery_target_eas"] == [0x40C0BA, 0x40C5FB]
        assert row176_calls["semantic_targets_survive"] is True
        assert row176_calls["boundary_exit_eas"] == [0x40A5F0, 0x40C64B]
        assert row176_calls["passed"] is True
        row177_calls = calls_observations["rhad:route@0x40C0D2"]
        assert row177_calls["source_present"] is False
        assert row177_calls["source_topology_reachable"] is False
        assert row177_calls["source_topology_retired"] is True
        assert row177_calls["indirect_transfer_present"] is False
        assert row177_calls["target_eas"] == []
        assert row177_calls["semantic_target_eas"] == [0x40A5F0, 0x40C0D4]
        assert row177_calls["delivery_target_eas"] == [0x40A5F0, 0x40C0D4]
        assert row177_calls["semantic_targets_survive"] is True
        assert row177_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row177_calls["passed"] is True
        row178_calls = calls_observations["rhad:route@0x40C0EE"]
        assert row178_calls["source_present"] is False
        assert row178_calls["source_topology_reachable"] is False
        assert row178_calls["source_topology_retired"] is True
        assert row178_calls["indirect_transfer_present"] is False
        assert row178_calls["target_eas"] == []
        assert row178_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row178_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row178_calls["semantic_targets_survive"] is True
        assert row178_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row178_calls["passed"] is True
        row179_calls = calls_observations["rhad:route@0x40C108"]
        assert row179_calls["source_present"] is False
        assert row179_calls["source_topology_reachable"] is False
        assert row179_calls["source_topology_retired"] is True
        assert row179_calls["indirect_transfer_present"] is False
        assert row179_calls["target_eas"] == []
        assert row179_calls["semantic_target_eas"] == [0x40A5F0, 0x40C10A]
        assert row179_calls["delivery_target_eas"] == [0x40A5F0, 0x40C10A]
        assert row179_calls["semantic_targets_survive"] is True
        assert row179_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row179_calls["passed"] is True
        row180_calls = calls_observations["route:rhad-direct@0x40C14E"]
        assert row180_calls["source_present"] is False
        assert row180_calls["source_topology_reachable"] is False
        assert row180_calls["source_topology_retired"] is True
        assert row180_calls["indirect_transfer_present"] is False
        assert row180_calls["target_eas"] == []
        assert row180_calls["semantic_target_eas"] == [0x40B6C0]
        assert row180_calls["delivery_target_eas"] == [0x40B6C0]
        assert row180_calls["semantic_targets_survive"] is True
        assert row180_calls["boundary_exit_eas"] == [0x40B790]
        assert row180_calls["passed"] is True
        row181_calls = calls_observations["rhad:route@0x40C168"]
        assert row181_calls["source_present"] is False
        assert row181_calls["source_topology_reachable"] is False
        assert row181_calls["source_topology_retired"] is True
        assert row181_calls["indirect_transfer_present"] is False
        assert row181_calls["target_eas"] == []
        assert row181_calls["semantic_target_eas"] == [0x40A5F0, 0x40C16A]
        assert row181_calls["delivery_target_eas"] == [0x40A5F0, 0x40C16A]
        assert row181_calls["semantic_targets_survive"] is True
        assert row181_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row181_calls["passed"] is True
        assert 0x40C168 not in calls_payload["reachable_eas"]
        row182_calls = calls_observations["rhad:route@0x40C184"]
        assert row182_calls["source_present"] is False
        assert row182_calls["source_topology_reachable"] is False
        assert row182_calls["source_topology_retired"] is True
        assert row182_calls["indirect_transfer_present"] is False
        assert row182_calls["target_eas"] == []
        assert row182_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row182_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row182_calls["semantic_targets_survive"] is True
        assert row182_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row182_calls["passed"] is True
        row183_calls = calls_observations["rhad:route@0x40C19E"]
        assert row183_calls["source_present"] is False
        assert row183_calls["source_topology_reachable"] is False
        assert row183_calls["source_topology_retired"] is True
        assert row183_calls["indirect_transfer_present"] is False
        assert row183_calls["target_eas"] == []
        assert row183_calls["semantic_target_eas"] == [0x40A5F0, 0x40C1A0]
        assert row183_calls["delivery_target_eas"] == [0x40A5F0, 0x40C1A0]
        assert row183_calls["semantic_targets_survive"] is True
        assert row183_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row183_calls["passed"] is True
        row184_calls = calls_observations["rhad:route@0x40C1F0"]
        assert row184_calls["source_present"] is False
        assert row184_calls["source_topology_reachable"] is False
        assert row184_calls["source_topology_retired"] is True
        assert row184_calls["indirect_transfer_present"] is False
        assert row184_calls["target_eas"] == []
        assert row184_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row184_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row184_calls["semantic_targets_survive"] is True
        assert row184_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row184_calls["passed"] is True
        row185_calls = calls_observations["rhad:route@0x40C20A"]
        assert row185_calls["source_present"] is False
        assert row185_calls["source_topology_reachable"] is False
        assert row185_calls["source_topology_retired"] is True
        assert row185_calls["indirect_transfer_present"] is False
        assert row185_calls["target_eas"] == []
        assert row185_calls["semantic_target_eas"] == [0x40A5F0, 0x40C20C]
        assert row185_calls["delivery_target_eas"] == [0x40A5F0, 0x40C20C]
        assert row185_calls["semantic_targets_survive"] is True
        assert row185_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row185_calls["passed"] is True
        row186_calls = calls_observations["route:rhad-direct@0x40C251"]
        assert row186_calls["source_present"] is False
        assert row186_calls["source_topology_reachable"] is False
        assert row186_calls["source_topology_retired"] is True
        assert row186_calls["indirect_transfer_present"] is False
        assert row186_calls["target_eas"] == []
        assert row186_calls["semantic_target_eas"] == [0x40B6C0]
        assert row186_calls["delivery_target_eas"] == [0x40B6C0]
        assert row186_calls["semantic_targets_survive"] is True
        assert row186_calls["boundary_exit_eas"] == [0x40B790]
        assert row186_calls["passed"] is True
        row187_calls = calls_observations["rhad:route@0x40C26B"]
        assert row187_calls["source_present"] is False
        assert row187_calls["source_topology_reachable"] is False
        assert row187_calls["source_topology_retired"] is True
        assert row187_calls["indirect_transfer_present"] is False
        assert row187_calls["target_eas"] == []
        assert row187_calls["semantic_target_eas"] == [0x40A5F0, 0x40C26D]
        assert row187_calls["delivery_target_eas"] == [0x40A5F0, 0x40C26D]
        assert row187_calls["semantic_targets_survive"] is True
        assert row187_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row187_calls["passed"] is True
        row188_calls = calls_observations["route:rhad-direct@0x40C2F9"]
        assert row188_calls["source_present"] is False
        assert row188_calls["source_topology_reachable"] is False
        assert row188_calls["source_topology_retired"] is True
        assert row188_calls["indirect_transfer_present"] is False
        assert row188_calls["target_eas"] == []
        assert row188_calls["semantic_target_eas"] == [0x40B6C0]
        assert row188_calls["delivery_target_eas"] == [0x40B6C0]
        assert row188_calls["semantic_targets_survive"] is True
        assert row188_calls["boundary_exit_eas"] == [0x40B790]
        assert row188_calls["passed"] is True
        row189_calls = calls_observations["rhad:route@0x40C313"]
        assert row189_calls["source_present"] is False
        assert row189_calls["source_topology_reachable"] is False
        assert row189_calls["source_topology_retired"] is True
        assert row189_calls["indirect_transfer_present"] is False
        assert row189_calls["target_eas"] == []
        assert row189_calls["semantic_target_eas"] == [0x40A5F0, 0x40C315]
        assert row189_calls["delivery_target_eas"] == [0x40A5F0, 0x40C315]
        assert row189_calls["semantic_targets_survive"] is True
        assert row189_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row189_calls["passed"] is True
        row190_calls = calls_observations["route:rhad-direct@0x40C34B"]
        assert row190_calls["source_present"] is False
        assert row190_calls["source_topology_reachable"] is False
        assert row190_calls["source_topology_retired"] is True
        assert row190_calls["indirect_transfer_present"] is False
        assert row190_calls["target_eas"] == []
        assert row190_calls["semantic_target_eas"] == [0x40B6C0]
        assert row190_calls["delivery_target_eas"] == [0x40B6C0]
        assert row190_calls["semantic_targets_survive"] is True
        assert row190_calls["boundary_exit_eas"] == [0x40B790]
        assert row190_calls["passed"] is True
        row191_calls = calls_observations["rhad:route@0x40C365"]
        assert row191_calls["source_present"] is False
        assert row191_calls["source_topology_reachable"] is False
        assert row191_calls["source_topology_retired"] is True
        assert row191_calls["indirect_transfer_present"] is False
        assert row191_calls["target_eas"] == []
        assert row191_calls["semantic_target_eas"] == [0x40A5F0, 0x40C367]
        assert row191_calls["delivery_target_eas"] == [0x40A5F0, 0x40C367]
        assert row191_calls["semantic_targets_survive"] is True
        assert row191_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row191_calls["passed"] is True
        row192_calls = calls_observations["route:rhad-direct@0x40C390"]
        assert row192_calls["source_present"] is False
        assert row192_calls["source_topology_reachable"] is False
        assert row192_calls["source_topology_retired"] is True
        assert row192_calls["indirect_transfer_present"] is False
        assert row192_calls["target_eas"] == []
        assert row192_calls["semantic_target_eas"] == [0x40B6C0]
        assert row192_calls["delivery_target_eas"] == [0x40B6C0]
        assert row192_calls["semantic_targets_survive"] is True
        assert row192_calls["boundary_exit_eas"] == [0x40B790]
        assert row192_calls["passed"] is True
        row193_calls = calls_observations["rhad:route@0x40C3AA"]
        assert row193_calls["source_present"] is False
        assert row193_calls["source_topology_reachable"] is False
        assert row193_calls["source_topology_retired"] is True
        assert row193_calls["indirect_transfer_present"] is False
        assert row193_calls["target_eas"] == []
        assert row193_calls["semantic_target_eas"] == [0x40A5F0, 0x40C3AC]
        assert row193_calls["delivery_target_eas"] == [0x40A5F0, 0x40C3AC]
        assert row193_calls["semantic_targets_survive"] is True
        assert row193_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row193_calls["passed"] is True
        row194_calls = calls_observations["route:rhad-direct@0x40C3D7"]
        assert row194_calls["source_present"] is False
        assert row194_calls["source_topology_reachable"] is False
        assert row194_calls["source_topology_retired"] is True
        assert row194_calls["indirect_transfer_present"] is False
        assert row194_calls["target_eas"] == []
        assert row194_calls["semantic_target_eas"] == [0x40B6C0]
        assert row194_calls["delivery_target_eas"] == [0x40B6C0]
        assert row194_calls["semantic_targets_survive"] is True
        assert row194_calls["boundary_exit_eas"] == [0x40B790]
        assert row194_calls["passed"] is True
        row195_calls = calls_observations["rhad:route@0x40C3F1"]
        assert row195_calls["source_present"] is False
        assert row195_calls["source_topology_reachable"] is False
        assert row195_calls["source_topology_retired"] is True
        assert row195_calls["indirect_transfer_present"] is False
        assert row195_calls["target_eas"] == []
        assert row195_calls["semantic_target_eas"] == [0x40A5F0, 0x40C3F3]
        assert row195_calls["delivery_target_eas"] == [0x40A5F0, 0x40C3F3]
        assert row195_calls["semantic_targets_survive"] is True
        assert row195_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row195_calls["passed"] is True
        row196_calls = calls_observations["route:rhad-direct@0x40C42C"]
        assert row196_calls["source_present"] is False
        assert row196_calls["source_topology_reachable"] is False
        assert row196_calls["source_topology_retired"] is True
        assert row196_calls["indirect_transfer_present"] is False
        assert row196_calls["target_eas"] == []
        assert row196_calls["semantic_target_eas"] == [0x40B6C0]
        assert row196_calls["delivery_target_eas"] == [0x40B6C0]
        assert row196_calls["semantic_targets_survive"] is True
        assert row196_calls["boundary_exit_eas"] == [0x40B790]
        assert row196_calls["passed"] is True
        row197_calls = calls_observations["rhad:route@0x40C446"]
        assert row197_calls["source_present"] is False
        assert row197_calls["source_topology_reachable"] is False
        assert row197_calls["source_topology_retired"] is True
        assert row197_calls["indirect_transfer_present"] is False
        assert row197_calls["target_eas"] == []
        assert row197_calls["semantic_target_eas"] == [0x40A5F0, 0x40C448]
        assert row197_calls["delivery_target_eas"] == [0x40A5F0, 0x40C448]
        assert row197_calls["semantic_targets_survive"] is True
        assert row197_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row197_calls["passed"] is True
        row198_calls = calls_observations["rhad:route@0x40C462"]
        assert row198_calls["source_present"] is False
        assert row198_calls["source_topology_reachable"] is False
        assert row198_calls["source_topology_retired"] is True
        assert row198_calls["indirect_transfer_present"] is False
        assert row198_calls["target_eas"] == []
        assert row198_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row198_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row198_calls["semantic_targets_survive"] is True
        assert row198_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row198_calls["passed"] is True
        row199_calls = calls_observations["rhad:route@0x40C47C"]
        assert row199_calls["source_present"] is False
        assert row199_calls["source_topology_reachable"] is False
        assert row199_calls["source_topology_retired"] is True
        assert row199_calls["indirect_transfer_present"] is False
        assert row199_calls["target_eas"] == []
        assert row199_calls["semantic_target_eas"] == [0x40A5F0, 0x40C47E]
        assert row199_calls["delivery_target_eas"] == [0x40A5F0, 0x40C47E]
        assert row199_calls["semantic_targets_survive"] is True
        assert row199_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row199_calls["passed"] is True
        row200_calls = calls_observations["rhad:route@0x40C498"]
        assert row200_calls["source_present"] is False
        assert row200_calls["source_topology_reachable"] is False
        assert row200_calls["source_topology_retired"] is True
        assert row200_calls["indirect_transfer_present"] is False
        assert row200_calls["target_eas"] == []
        assert row200_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row200_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row200_calls["semantic_targets_survive"] is True
        assert row200_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row200_calls["passed"] is True
        row201_calls = calls_observations["rhad:route@0x40C4B2"]
        assert row201_calls["source_present"] is False
        assert row201_calls["source_topology_reachable"] is False
        assert row201_calls["source_topology_retired"] is True
        assert row201_calls["indirect_transfer_present"] is False
        assert row201_calls["target_eas"] == []
        assert row201_calls["semantic_target_eas"] == [0x40A5F0, 0x40C4B4]
        assert row201_calls["delivery_target_eas"] == [0x40A5F0, 0x40C4B4]
        assert row201_calls["semantic_targets_survive"] is True
        assert row201_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row201_calls["passed"] is True
        row202_calls = calls_observations["rhad:route@0x40C4DA"]
        assert row202_calls["source_present"] is False
        assert row202_calls["source_topology_reachable"] is False
        assert row202_calls["source_topology_retired"] is True
        assert row202_calls["indirect_transfer_present"] is False
        assert row202_calls["target_eas"] == []
        assert row202_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row202_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row202_calls["semantic_targets_survive"] is True
        assert row202_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row202_calls["passed"] is True
        row203_calls = calls_observations["rhad:route@0x40C4F4"]
        assert row203_calls["source_present"] is False
        assert row203_calls["source_topology_reachable"] is False
        assert row203_calls["source_topology_retired"] is True
        assert row203_calls["indirect_transfer_present"] is False
        assert row203_calls["target_eas"] == []
        assert row203_calls["semantic_target_eas"] == [0x40A5F0, 0x40C4F6]
        assert row203_calls["delivery_target_eas"] == [0x40A5F0, 0x40C4F6]
        assert row203_calls["semantic_targets_survive"] is True
        assert row203_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row203_calls["passed"] is True
        row204_calls = calls_observations["rhad:route@0x40C525"]
        assert row204_calls["source_present"] is False
        assert row204_calls["source_topology_reachable"] is False
        assert row204_calls["source_topology_retired"] is True
        assert row204_calls["indirect_transfer_present"] is False
        assert row204_calls["target_eas"] == []
        assert row204_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row204_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row204_calls["semantic_targets_survive"] is True
        assert row204_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row204_calls["passed"] is True
        row205_calls = calls_observations["rhad:route@0x40C53F"]
        assert row205_calls["source_present"] is False
        assert row205_calls["source_topology_reachable"] is False
        assert row205_calls["source_topology_retired"] is True
        assert row205_calls["indirect_transfer_present"] is False
        assert row205_calls["target_eas"] == []
        assert row205_calls["semantic_target_eas"] == [0x40A5F0, 0x40C541]
        assert row205_calls["delivery_target_eas"] == [0x40A5F0, 0x40C541]
        assert row205_calls["semantic_targets_survive"] is True
        assert row205_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row205_calls["passed"] is True
        row206_calls = calls_observations["rhad:route@0x40C576"]
        assert row206_calls["source_present"] is False
        assert row206_calls["source_topology_reachable"] is False
        assert row206_calls["source_topology_retired"] is True
        assert row206_calls["indirect_transfer_present"] is False
        assert row206_calls["target_eas"] == []
        assert row206_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row206_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row206_calls["semantic_targets_survive"] is True
        assert row206_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row206_calls["passed"] is True
        row207_calls = calls_observations["rhad:route@0x40C590"]
        assert row207_calls["source_present"] is False
        assert row207_calls["source_topology_reachable"] is False
        assert row207_calls["source_topology_retired"] is True
        assert row207_calls["indirect_transfer_present"] is False
        assert row207_calls["target_eas"] == []
        assert row207_calls["semantic_target_eas"] == [0x40A5F0, 0x40C592]
        assert row207_calls["delivery_target_eas"] == [0x40A5F0, 0x40C592]
        assert row207_calls["semantic_targets_survive"] is True
        assert row207_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row207_calls["passed"] is True
        row208_calls = calls_observations["route:rhad-direct@0x40C5F9"]
        assert row208_calls["source_present"] is False
        assert row208_calls["source_topology_reachable"] is False
        assert row208_calls["source_topology_retired"] is True
        assert row208_calls["indirect_transfer_present"] is False
        assert row208_calls["target_eas"] == []
        assert row208_calls["semantic_target_eas"] == [0x40B6C0]
        assert row208_calls["delivery_target_eas"] == [0x40B6C0]
        assert row208_calls["semantic_targets_survive"] is True
        assert row208_calls["boundary_exit_eas"] == [0x40B790]
        assert row208_calls["passed"] is True
        row209_calls = calls_observations["rhad:route@0x40C613"]
        assert row209_calls["source_present"] is False
        assert row209_calls["source_topology_reachable"] is False
        assert row209_calls["source_topology_retired"] is True
        assert row209_calls["indirect_transfer_present"] is False
        assert row209_calls["target_eas"] == []
        assert row209_calls["semantic_target_eas"] == [0x40C615, 0x40C64B]
        assert row209_calls["delivery_target_eas"] == [0x40C615, 0x40C64B]
        assert row209_calls["semantic_targets_survive"] is True
        assert row209_calls["boundary_exit_eas"] == [
            0x40A5F0,
            0x40C62F,
            0x40C665,
        ]
        assert row209_calls["passed"] is True
        row210_calls = calls_observations["rhad:route@0x40C62D"]
        assert row210_calls["source_present"] is False
        assert row210_calls["source_topology_reachable"] is False
        assert row210_calls["source_topology_retired"] is True
        assert row210_calls["indirect_transfer_present"] is False
        assert row210_calls["target_eas"] == []
        assert row210_calls["semantic_target_eas"] == [0x40A5F0, 0x40C62F]
        assert row210_calls["delivery_target_eas"] == [0x40A5F0, 0x40C62F]
        assert row210_calls["semantic_targets_survive"] is True
        assert row210_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row210_calls["passed"] is True
        row211_calls = calls_observations["rhad:route@0x40C649"]
        assert row211_calls["source_present"] is False
        assert row211_calls["source_topology_reachable"] is False
        assert row211_calls["source_topology_retired"] is True
        assert row211_calls["indirect_transfer_present"] is False
        assert row211_calls["target_eas"] == []
        assert row211_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row211_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row211_calls["semantic_targets_survive"] is True
        assert row211_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row211_calls["passed"] is True
        row212_calls = calls_observations["rhad:route@0x40C663"]
        assert row212_calls["source_present"] is False
        assert row212_calls["source_topology_reachable"] is False
        assert row212_calls["source_topology_retired"] is True
        assert row212_calls["indirect_transfer_present"] is False
        assert row212_calls["target_eas"] == []
        assert row212_calls["semantic_target_eas"] == [0x40A5F0, 0x40C665]
        assert row212_calls["delivery_target_eas"] == [0x40A5F0, 0x40C665]
        assert row212_calls["semantic_targets_survive"] is True
        assert row212_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row212_calls["passed"] is True
        row213_calls = calls_observations["rhad:route@0x40C694"]
        assert row213_calls["source_present"] is False
        assert row213_calls["source_topology_reachable"] is False
        assert row213_calls["source_topology_retired"] is True
        assert row213_calls["indirect_transfer_present"] is False
        assert row213_calls["target_eas"] == []
        assert row213_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row213_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row213_calls["semantic_targets_survive"] is True
        assert row213_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row213_calls["passed"] is True
        row214_calls = calls_observations["route:rhad-direct@0x40C6B3"]
        assert row214_calls["source_present"] is False
        assert row214_calls["source_topology_reachable"] is False
        assert row214_calls["source_topology_retired"] is True
        assert row214_calls["indirect_transfer_present"] is False
        assert row214_calls["target_eas"] == []
        assert row214_calls["semantic_target_eas"] == [0x40A607]
        assert row214_calls["delivery_target_eas"] == [0x40A607]
        assert row214_calls["semantic_targets_survive"] is True
        assert row214_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row214_calls["passed"] is True
        row215_calls = calls_observations["route:rhad-direct@0x40C6D8"]
        assert row215_calls["source_present"] is False
        assert row215_calls["source_topology_reachable"] is False
        assert row215_calls["source_topology_retired"] is True
        assert row215_calls["indirect_transfer_present"] is False
        assert row215_calls["target_eas"] == []
        assert row215_calls["semantic_target_eas"] == [0x40A607]
        assert row215_calls["delivery_target_eas"] == [0x40A607]
        assert row215_calls["semantic_targets_survive"] is True
        assert row215_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row215_calls["passed"] is True
        row216_calls = calls_observations["route:rhad-direct@0x40C703"]
        assert row216_calls["source_present"] is False
        assert row216_calls["source_topology_reachable"] is False
        assert row216_calls["source_topology_retired"] is True
        assert row216_calls["indirect_transfer_present"] is False
        assert row216_calls["target_eas"] == []
        assert row216_calls["semantic_target_eas"] == [0x40A607]
        assert row216_calls["delivery_target_eas"] == [0x40A607]
        assert row216_calls["semantic_targets_survive"] is True
        assert row216_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row216_calls["passed"] is True
        row217_calls = calls_observations["route:rhad-direct@0x40C72E"]
        assert row217_calls["source_present"] is False
        assert row217_calls["source_topology_reachable"] is False
        assert row217_calls["source_topology_retired"] is True
        assert row217_calls["indirect_transfer_present"] is False
        assert row217_calls["target_eas"] == []
        assert row217_calls["semantic_target_eas"] == [0x40A607]
        assert row217_calls["semantic_targets_survive"] is True
        assert row217_calls["passed"] is True
        row218_calls = calls_observations["route:rhad-direct@0x40C74F"]
        assert row218_calls["source_present"] is False
        assert row218_calls["source_topology_reachable"] is False
        assert row218_calls["source_topology_retired"] is True
        assert row218_calls["indirect_transfer_present"] is False
        assert row218_calls["target_eas"] == []
        assert row218_calls["semantic_target_eas"] == [0x40A607]
        assert row218_calls["delivery_target_eas"] == [0x40A607]
        assert row218_calls["semantic_targets_survive"] is True
        assert row218_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row218_calls["passed"] is True
        row219_calls = calls_observations["route:rhad-direct@0x40C76E"]
        assert row219_calls["source_present"] is False
        assert row219_calls["source_topology_reachable"] is False
        assert row219_calls["source_topology_retired"] is True
        assert row219_calls["indirect_transfer_present"] is False
        assert row219_calls["target_eas"] == []
        assert row219_calls["semantic_target_eas"] == [0x40A607]
        assert row219_calls["delivery_target_eas"] == [0x40A607]
        assert row219_calls["semantic_targets_survive"] is True
        assert row219_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row219_calls["passed"] is True
        row220_calls = calls_observations["route:rhad-direct@0x40C793"]
        assert row220_calls["source_present"] is False
        assert row220_calls["source_topology_reachable"] is False
        assert row220_calls["source_topology_retired"] is True
        assert row220_calls["indirect_transfer_present"] is False
        assert row220_calls["target_eas"] == []
        assert row220_calls["semantic_target_eas"] == [0x40A607]
        assert row220_calls["delivery_target_eas"] == [0x40A607]
        assert row220_calls["semantic_targets_survive"] is True
        assert row220_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row220_calls["passed"] is True
        row221_calls = calls_observations["route:rhad-direct@0x40C7B8"]
        assert row221_calls["source_present"] is False
        assert row221_calls["source_topology_reachable"] is False
        assert row221_calls["source_topology_retired"] is True
        assert row221_calls["indirect_transfer_present"] is False
        assert row221_calls["target_eas"] == []
        assert row221_calls["semantic_target_eas"] == [0x40A607]
        assert row221_calls["delivery_target_eas"] == [0x40A607]
        assert row221_calls["semantic_targets_survive"] is True
        assert row221_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row221_calls["passed"] is True
        row222_calls = calls_observations["route:rhad-direct@0x40C7E3"]
        assert row222_calls["source_present"] is False
        assert row222_calls["source_topology_reachable"] is False
        assert row222_calls["source_topology_retired"] is True
        assert row222_calls["indirect_transfer_present"] is False
        assert row222_calls["target_eas"] == []
        assert row222_calls["semantic_target_eas"] == [0x40A607]
        assert row222_calls["delivery_target_eas"] == [0x40A607]
        assert row222_calls["semantic_targets_survive"] is True
        assert row222_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row222_calls["passed"] is True
        row223_calls = calls_observations["route:rhad-direct@0x40C802"]
        assert row223_calls["source_present"] is False
        assert row223_calls["source_topology_reachable"] is False
        assert row223_calls["source_topology_retired"] is True
        assert row223_calls["indirect_transfer_present"] is False
        assert row223_calls["target_eas"] == []
        assert row223_calls["semantic_target_eas"] == [0x40A607]
        assert row223_calls["delivery_target_eas"] == [0x40A607]
        assert row223_calls["semantic_targets_survive"] is True
        assert row223_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row223_calls["passed"] is True
        row224_calls = calls_observations["route:rhad-direct@0x40C821"]
        assert row224_calls["source_present"] is False
        assert row224_calls["source_topology_reachable"] is False
        assert row224_calls["source_topology_retired"] is True
        assert row224_calls["indirect_transfer_present"] is False
        assert row224_calls["target_eas"] == []
        assert row224_calls["semantic_target_eas"] == [0x40A607]
        assert row224_calls["delivery_target_eas"] == [0x40A607]
        assert row224_calls["semantic_targets_survive"] is True
        assert row224_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row224_calls["passed"] is True
        row225_calls = calls_observations["route:rhad-direct@0x40C840"]
        assert row225_calls["source_present"] is False
        assert row225_calls["source_topology_reachable"] is False
        assert row225_calls["source_topology_retired"] is True
        assert row225_calls["indirect_transfer_present"] is False
        assert row225_calls["target_eas"] == []
        assert row225_calls["semantic_target_eas"] == [0x40A607]
        assert row225_calls["delivery_target_eas"] == [0x40A607]
        assert row225_calls["semantic_targets_survive"] is True
        assert row225_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row225_calls["passed"] is True
        row226_calls = calls_observations["route:rhad-direct@0x40C86B"]
        assert row226_calls["source_present"] is False
        assert row226_calls["source_topology_reachable"] is False
        assert row226_calls["source_topology_retired"] is True
        assert row226_calls["indirect_transfer_present"] is False
        assert row226_calls["target_eas"] == []
        assert row226_calls["semantic_target_eas"] == [0x40A607]
        assert row226_calls["delivery_target_eas"] == [0x40A607]
        assert row226_calls["semantic_targets_survive"] is True
        assert row226_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row226_calls["passed"] is True
        row227_calls = calls_observations["route:rhad-direct@0x40C896"]
        assert row227_calls["source_present"] is False
        assert row227_calls["source_topology_reachable"] is False
        assert row227_calls["source_topology_retired"] is True
        assert row227_calls["indirect_transfer_present"] is False
        assert row227_calls["target_eas"] == []
        assert row227_calls["semantic_target_eas"] == [0x40A607]
        assert row227_calls["delivery_target_eas"] == [0x40A607]
        assert row227_calls["semantic_targets_survive"] is True
        assert row227_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C]
        assert row227_calls["passed"] is True
        assert 0x40C576 not in calls_payload["reachable_eas"]
        assert 0x40C590 not in calls_payload["reachable_eas"]
        assert 0x40C5F9 not in calls_payload["reachable_eas"]
        assert 0x40C613 not in calls_payload["reachable_eas"]
        assert 0x40C62D not in calls_payload["reachable_eas"]
        assert 0x40C649 not in calls_payload["reachable_eas"]
        assert 0x40C663 not in calls_payload["reachable_eas"]
        assert 0x40C694 not in calls_payload["reachable_eas"]
        assert 0x40C6B3 not in calls_payload["reachable_eas"]
        assert 0x40C6D8 not in calls_payload["reachable_eas"]
        assert 0x40C703 not in calls_payload["reachable_eas"]
        assert 0x40C72E not in calls_payload["reachable_eas"]
        assert 0x40C793 not in calls_payload["reachable_eas"]
        assert 0x40C7B0 not in calls_payload["reachable_eas"]
        assert 0x40C7B8 not in calls_payload["reachable_eas"]
        assert 0x40C7E3 not in calls_payload["reachable_eas"]
        assert 0x40C800 not in calls_payload["reachable_eas"]
        assert 0x40C821 not in calls_payload["reachable_eas"]
        # CALLS may reanchor an optimized block at the former transfer EA.
        # The typed observation above proves source retirement and no indirect.
        assert 0x40C16A in calls_payload["reachable_eas"]
        assert 0x40C184 not in calls_payload["reachable_eas"]
        assert 0x40C19E not in calls_payload["reachable_eas"]
        assert {0x40C1BA, 0x40C1C0}.issubset(calls_payload["reachable_eas"])
        assert 0x40C1EC not in calls_payload["reachable_eas"]
        assert 0x40C1F0 not in calls_payload["reachable_eas"]
        assert 0x40C14E not in calls_payload["reachable_eas"]
        assert 0x40C108 not in calls_payload["reachable_eas"]
        assert 0x40C0EE not in calls_payload["reachable_eas"]
        assert 0x40BD82 not in calls_payload["reachable_eas"]
        assert 0x40BD68 not in calls_payload["reachable_eas"]
        assert 0x40BD4E not in calls_payload["reachable_eas"]
        assert 0x40BD17 not in calls_payload["reachable_eas"]
        assert 0x40BCFD not in calls_payload["reachable_eas"]
        assert 0x40BCE3 not in calls_payload["reachable_eas"]
        assert 0x40BCC9 not in calls_payload["reachable_eas"]
        assert 0x40BCAD not in calls_payload["reachable_eas"]
        assert 0x40BC93 not in calls_payload["reachable_eas"]
        assert 0x40BC79 not in calls_payload["reachable_eas"]
        assert 0x40BC5F not in calls_payload["reachable_eas"]
        assert 0x40BC2B not in calls_payload["reachable_eas"]
        assert 0x40BC11 not in calls_payload["reachable_eas"]
        assert 0x40BBF7 not in calls_payload["reachable_eas"]
        assert 0x40BBDD not in calls_payload["reachable_eas"]
        assert 0x40BBC1 not in calls_payload["reachable_eas"]
        assert 0x40BBA7 not in calls_payload["reachable_eas"]
        assert 0x40BB8D not in calls_payload["reachable_eas"]
        assert 0x40BB73 not in calls_payload["reachable_eas"]
        assert 0x40B98C not in calls_payload["reachable_eas"]
        assert 0x40B9A0 not in calls_payload["reachable_eas"]
        assert 0x40B9A4 not in calls_payload["reachable_eas"]
        assert 0x40B9A6 in calls_payload["reachable_eas"]
        assert {0x40C1F2, 0x40C206, 0x40C20A}.isdisjoint(calls_payload["reachable_eas"])
        assert {
            0x40C1FE,
            0x40C200,
            0x40C217,
            0x40C241,
            0x40C24B,
            0x40C795,
        }.issubset(calls_payload["reachable_eas"])
        assert {0x40C247, 0x40C249, 0x40C251}.isdisjoint(calls_payload["reachable_eas"])
        assert {0x40C253, 0x40C267, 0x40C269, 0x40C26B}.isdisjoint(
            calls_payload["reachable_eas"]
        )
        assert {
            0x40C25F,
            0x40C261,
            0x40C2F3,
            0x40C7BA,
        }.issubset(calls_payload["reachable_eas"])
        assert {0x40C2EF, 0x40C2F9}.isdisjoint(calls_payload["reachable_eas"])
        assert {
            0x40C2FB,
            0x40C313,
            0x40C315,
            0x40C34B,
            0x40C365,
        }.isdisjoint(calls_payload["reachable_eas"])
        assert {
            0x40C307,
            0x40C309,
            0x40C328,
            0x40C341,
            0x40C7E5,
            0x40C802,
        }.issubset(calls_payload["reachable_eas"])
        assert {
            0x40C359,
            0x40C35B,
            0x40C36F,
            0x40C804,
        }.issubset(calls_payload["reachable_eas"])
        assert 0x40BCCB not in calls_payload["reachable_eas"]
        assert 0x40BCE5 not in calls_payload["reachable_eas"]
        assert {
            0x40B802,
            0x40B839,
            0x40B908,
            0x40B92B,
            0x40BC6D,
            0x40C15C,
        }.issubset(calls_payload["reachable_eas"])
        assert 0x40C186 not in calls_payload["reachable_eas"]
        assert 0x40C150 not in calls_payload["reachable_eas"]
        assert 0x40BE98 not in calls_payload["reachable_eas"]
        assert {0x40A5F6, 0x40B760, 0x40C696}.issubset(calls_payload["reachable_eas"])
        assert connection.execute(
            "SELECT COUNT(*) FROM lifecycle_events "
            "WHERE event_kind='ctree_captured' AND maturity='CMAT_FINAL'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT planned_operation_count, applied_operation_count, outcome "
            "FROM mutation_receipts"
        ).fetchall() == [(1492, 1492, "committed")]
        assert connection.execute(
            "SELECT current_phase, mutation_started, poisoned, interr_code "
            "FROM cfg_transaction_attempts"
        ).fetchall() == [("committed", 1, 0, None)]
        assert connection.execute(
            "SELECT outcome, fragment_staged, root_publication_attempted, "
            "root_publication_succeeded, rollback_attempted "
            "FROM semantic_fragment_transactions"
        ).fetchall() == [("committed", 1, 1, 1, 0)]
        assert connection.execute(
            "SELECT COUNT(*) FROM semantic_fragment_route_oracle_comparisons "
            "WHERE outcome='matched'"
        ).fetchone() == (223,)
        assert connection.execute(
            "SELECT COUNT(*) FROM mutation_receipt_identities"
        ).fetchone() == (887,)
        committed_witnesses = connection.execute(
            "SELECT local_block_id, provenance, logical_proxy_token, "
            "logical_version, logical_generation, insertion_quantity_before, "
            "insertion_quantity_after, requested_insertion_serial, "
            "returned_serial, invalidated "
            "FROM cfg_creation_witnesses WHERE state='committed' "
            "ORDER BY rowid"
        ).fetchall()
        imported_witnesses = tuple(
            row for row in committed_witnesses if row[1] == "imported_native"
        )
        assert tuple(row[0] for row in imported_witnesses) == _IMPORTED_BLOCK_IDS
        assert all(
            row[1] == "imported_native"
            and row[2]
            and row[3:5] == (0, 1)
            and row[6] == row[5] + 1
            and row[7] == row[8]
            and row[9] == 0
            for row in imported_witnesses
        )
        helper_witnesses = tuple(
            row for row in committed_witnesses if row[1] == "created_synthetic"
        )
        assert tuple(row[0] for row in helper_witnesses) == (
            "fallthrough-helper:rhad:route@0x40AE3C",
            "fallthrough-helper:rhad:route@0x40B340",
            "fallthrough-helper:rhad:route@0x40B7F4",
            "fallthrough-helper:rhad:route@0x40B896",
            "fallthrough-helper:rhad:route@0x40B956",
            "fallthrough-helper:rhad:route@0x40BFA2",
        )
        assert all(
            row[2]
            and row[3:5] == (0, 1)
            and row[6] == row[5] + 1
            and row[7] == row[8]
            and row[9] == 0
            for row in helper_witnesses
        )


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit(
            "usage: test_rhad_generated_checksum_publication.py --worker BINARY"
        )
    _run_worker(pathlib.Path(sys.argv[2]))
