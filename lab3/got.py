#int index[689] = {606, 641, 175, 1272, 1276, 286, 249, 502, 284, 208, 280, 541, 206, 786, 1237, 1008, 788, 704, 741, 1045, 1235, 738, 706, 1239, 1152, 849, 775, 1004, 1193, 1156, 771, 1191, 200, 380, 1309, 1136, 847, 877, 808, 57, 1132, 1134, 841, 1348, 1346, 10, 1291, 884, 1293, 1385, 300, 473, 1250, 304, 949, 1254, 1217, 1446, 1409, 1256, 947, 1219, 1407, 1215, 1448, 945, 908, 906, 943, 96, 986, 1213, 180, 1211, 141, 591, 558, 108, 519, 556, 432, 1186, 597, 147, 1149, 430, 92, 1147, 182, 145, 631, 1188, 149, 186, 1284, 684, 238, 680, 511, 273, 234, 102, 271, 550, 513, 799, 711, 1019, 1421, 28, 26, 782, 1184, 1015, 1011, 1013, 391, 317, 315, 230, 866, 1332, 834, 20, 22, 1082, 871, 873, 1260, 1379, 1338, 1221, 429, 466, 1084, 1373, 427, 313, 311, 1377, 1225, 921, 1418, 1451, 1049, 1414, 953, 1160, 990, 157, 568, 1457, 1121, 155, 566, 67, 153, 114, 529, 527, 112, 562, 460, 61, 421, 1175, 639, 676, 159, 620, 637, 674, 635, 624, 1313, 1179, 261, 226, 224, 1258, 758, 720, 1026, 523, 1067, 756, 265, 754, 719, 1063, 761, 717, 269, 797, 4, 328, 326, 222, 829, 898, 1114, 369, 220, 827, 367, 1321, 825, 851, 814, 2, 1360, 823, 33, 1093, 1232, 862, 864, 1362, 457, 1230, 1097, 860, 1095, 492, 418, 416, 451, 1056, 1423, 1368, 320, 1234, 929, 498, 1099, 927, 925, 1464, 1468, 129, 960, 1110, 164, 577, 76, 538, 575, 160, 573, 70, 412, 1306, 698, 651, 1125, 628, 663, 1300, 1129, 661, 1304, 299, 254, 1266, 1264, 534, 571, 769, 776, 1074, 293, 532, 1406, 291, 1268, 47, 1072, 728, 1035, 1229, 726, 6, 1166, 1400, 374, 339, 337, 801, 1144, 1107, 1356, 857, 1354, 1317, 45, 1142, 805, 1105, 855, 43, 853, 816, 894, 896, 1103, 892, 1391, 1101, 448, 446, 409, 1399, 407, 1434, 1069, 333, 1246, 1395, 331, 989, 901, 1471, 933, 903, 1242, 1203, 489, 1436, 1473, 974, 970, 1475, 583, 133, 548, 581, 546, 84, 1140, 509, 601, 139, 687, 440, 403, 1116, 659, 1331, 642, 607, 657, 176, 1273, 692, 285, 248, 1040, 283, 244, 501, 242, 739, 785, 505, 701, 287, 787, 1279, 58, 1007, 772, 1001, 1151, 50, 1192, 240, 203, 307, 15, 201, 876, 1194, 1345, 1137, 56, 1308, 1133, 1347, 807, 842, 885, 1198, 1388, 1380, 439, 437, 470, 433, 1445, 340, 1255, 1218, 1386, 956, 946, 993, 1212, 944, 995, 97, 1251, 1253, 983, 95, 985, 144, 981, 142, 109, 590, 557, 518, 598, 185, 1148, 630, 183, 648, 632, 189, 634, 646, 1189, 1090, 609, 683, 685, 1283, 1051, 235, 512, 272, 1285, 101, 551, 710, 748, 278, 239, 712, 709, 1287, 25, 744, 707, 1016, 1185, 1012, 783, 396, 318, 355, 27, 1333, 23, 1337, 822, 1370, 1335, 872, 1374, 1085, 870, 469, 467, 351, 919, 1413, 920, 1450, 969, 1415, 999, 952, 954, 117, 567, 1120, 154, 950, 115, 1454, 1419, 152, 528, 563, 113, 111, 561, 62, 424, 461, 1351, 621, 677, 158, 1316, 1353, 569, 660, 199, 1312, 636, 1176, 1310, 262, 520, 260, 757, 1027, 1259, 1021, 718, 753, 716, 751, 1023, 760, 1064, 794, 796, 329, 5, 360, 38, 897, 368, 221, 1115, 828, 366, 1, 1363, 3, 811, 1326, 850, 1361, 1324, 1365, 30, 865, 497, 1231, 321, 1424, 499, 1055, 1422, 930, 1059, 1426, 924, 961, 963, 1469, 77, 1098, 1461, 1111, 163, 126, 539, 576, 1463, 537, 124, 574, 411, 73, 572, 75, 450, 415, 1126, 71, 1467, 169, 413, 697, 1342, 167, 650, 613, 1169, 699, 629, 1128, 662, 1263, 290, 218, 533, 120, 777, 259, 531, 766, 729, 779, 257, 1226, 1032, 764, 1071, 1034, 762, 48, 1401, 1073, 1163, 7, 1167, 1269, 1165, 338, 334, 1318, 1355, 212, 377, 800, 856, 375, 1390, 817, 854, 852, 1143, 1359, 1106, 1398, 44, 1280, 893, 1396, 1282, 1394, 891, 482, 480, 408, 332, 988, 900, 330, 1206, 902, 1247, 1068, 936, 1208, 1433, 1243, 1204, 1437, 932, 1182, 87, 977, 1202, 179, 971, 134, 584, 1180, 1200, 132, 545, 508, 543, 443, 406, 1117, 81, 173, 1476, 171, 688};
#int got[689] = {0x17a30, 0x17a38, 0x17a40, 0x17a48, 0x17a50, 0x17a58, 0x17a60, 0x17a68, 0x17a70, 0x17a78, 0x17a80, 0x17a88, 0x17a90, 0x17a98, 0x17aa0, 0x17aa8, 0x17ab0, 0x17ab8, 0x17ac0, 0x17ac8, 0x17ad0, 0x17ad8, 0x17ae0, 0x17ae8, 0x17af0, 0x17af8, 0x17b00, 0x17b08, 0x17b10, 0x17b18, 0x17b20, 0x17b28, 0x17b30, 0x17b38, 0x17b40, 0x17b48, 0x17b50, 0x17b58, 0x17b60, 0x17b68, 0x17b70, 0x17b78, 0x17b80, 0x17b88, 0x17b90, 0x17b98, 0x17ba0, 0x17ba8, 0x17bb0, 0x17bb8, 0x17bc0, 0x17bc8, 0x17bd0, 0x17bd8, 0x17be0, 0x17be8, 0x17bf0, 0x17bf8, 0x17c00, 0x17c08, 0x17c10, 0x17c18, 0x17c20, 0x17c28, 0x17c30, 0x17c38, 0x17c40, 0x17c48, 0x17c50, 0x17c58, 0x17c60, 0x17c68, 0x17c70, 0x17c78, 0x17c80, 0x17c88, 0x17c90, 0x17c98, 0x17ca0, 0x17ca8, 0x17cb0, 0x17cb8, 0x17cc0, 0x17cc8, 0x17cd0, 0x17cd8, 0x17ce0, 0x17ce8, 0x17cf0, 0x17cf8, 0x17d00, 0x17d08, 0x17d10, 0x17d18, 0x17d20, 0x17d28, 0x17d30, 0x17d38, 0x17d40, 0x17d48, 0x17d50, 0x17d58, 0x17d60, 0x17d68, 0x17d70, 0x17d78, 0x17d80, 0x17d88, 0x17d90, 0x17d98, 0x17da0, 0x17da8, 0x17db0, 0x17db8, 0x17dc0, 0x17dc8, 0x17dd0, 0x17dd8, 0x17de0, 0x17de8, 0x17df0, 0x17df8, 0x17e00, 0x17e08, 0x17e10, 0x17e18, 0x17e20, 0x17e28, 0x17e30, 0x17e38, 0x17e40, 0x17e48, 0x17e50, 0x17e58, 0x17e60, 0x17e68, 0x17e70, 0x17e78, 0x17e80, 0x17e88, 0x17e90, 0x17e98, 0x17ea0, 0x17ea8, 0x17eb0, 0x17eb8, 0x17ec0, 0x17ec8, 0x17ed0, 0x17ed8, 0x17ee0, 0x17ee8, 0x17ef0, 0x17ef8, 0x17f00, 0x17f08, 0x17f10, 0x17f18, 0x17f20, 0x17f28, 0x17f30, 0x17f38, 0x17f40, 0x17f48, 0x17f50, 0x17f58, 0x17f60, 0x17f68, 0x17f70, 0x17f78, 0x17f80, 0x17f88, 0x17f90, 0x17f98, 0x17fa0, 0x17fa8, 0x17fb0, 0x17fb8, 0x17fc8, 0x17fd0, 0x17fd8, 0x17fe0, 0x17fe8, 0x17ff0, 0x17ff8, 0x18000, 0x18008, 0x18010, 0x18018, 0x18020, 0x18028, 0x18030, 0x18038, 0x18040, 0x18048, 0x18050, 0x18058, 0x18060, 0x18068, 0x18070, 0x18078, 0x18080, 0x18088, 0x18090, 0x18098, 0x180a0, 0x180a8, 0x180b0, 0x180b8, 0x180c0, 0x180c8, 0x180d0, 0x180d8, 0x180e0, 0x180e8, 0x180f0, 0x180f8, 0x18100, 0x18108, 0x18110, 0x18118, 0x18120, 0x18128, 0x18130, 0x18138, 0x18140, 0x18148, 0x18150, 0x18158, 0x18160, 0x18168, 0x18170, 0x18178, 0x18180, 0x18188, 0x18190, 0x18198, 0x181a0, 0x181a8, 0x181b0, 0x181b8, 0x181c0, 0x181c8, 0x181d0, 0x181d8, 0x181e0, 0x181e8, 0x181f0, 0x181f8, 0x18200, 0x18208, 0x18210, 0x18218, 0x18220, 0x18228, 0x18230, 0x18238, 0x18240, 0x18248, 0x18250, 0x18258, 0x18260, 0x18268, 0x18270, 0x18278, 0x18280, 0x18288, 0x18290, 0x18298, 0x182a0, 0x182a8, 0x182b0, 0x182b8, 0x182c0, 0x182c8, 0x182d0, 0x182d8, 0x182e0, 0x182e8, 0x182f0, 0x182f8, 0x18300, 0x18308, 0x18310, 0x18318, 0x18320, 0x18328, 0x18330, 0x18338, 0x18340, 0x18348, 0x18350, 0x18358, 0x18360, 0x18368, 0x18370, 0x18378, 0x18380, 0x18388, 0x18390, 0x18398, 0x183a0, 0x183a8, 0x183b0, 0x183b8, 0x183c0, 0x183c8, 0x183d0, 0x183d8, 0x183e0, 0x183e8, 0x183f0, 0x183f8, 0x18400, 0x18408, 0x18410, 0x18418, 0x18428, 0x18430, 0x18438, 0x18440, 0x18448, 0x18450, 0x18458, 0x18460, 0x18468, 0x18470, 0x18478, 0x18480, 0x18488, 0x18490, 0x18498, 0x184a0, 0x184a8, 0x184b0, 0x184b8, 0x184c0, 0x184c8, 0x184d0, 0x184d8, 0x184e0, 0x184e8, 0x184f0, 0x184f8, 0x18500, 0x18508, 0x18510, 0x18518, 0x18520, 0x18528, 0x18530, 0x18538, 0x18540, 0x18548, 0x18550, 0x18558, 0x18568, 0x18570, 0x18578, 0x18580, 0x18588, 0x18590, 0x18598, 0x185a0, 0x185a8, 0x185b0, 0x185b8, 0x185c0, 0x185c8, 0x185d0, 0x185d8, 0x185e0, 0x185e8, 0x185f0, 0x185f8, 0x18600, 0x18608, 0x18610, 0x18618, 0x18620, 0x18628, 0x18630, 0x18638, 0x18640, 0x18648, 0x18650, 0x18658, 0x18660, 0x18668, 0x18670, 0x18678, 0x18680, 0x18688, 0x18690, 0x18698, 0x186a0, 0x186a8, 0x186b0, 0x186b8, 0x186c0, 0x186c8, 0x186d0, 0x186d8, 0x186e0, 0x186e8, 0x186f0, 0x186f8, 0x18700, 0x18708, 0x18710, 0x18718, 0x18720, 0x18728, 0x18730, 0x18738, 0x18740, 0x18748, 0x18750, 0x18758, 0x18760, 0x18768, 0x18770, 0x18778, 0x18780, 0x18788, 0x18790, 0x18798, 0x187a0, 0x187a8, 0x187b0, 0x187b8, 0x187c0, 0x187c8, 0x187d0, 0x187d8, 0x187e0, 0x187e8, 0x187f0, 0x187f8, 0x18800, 0x18808, 0x18810, 0x18818, 0x18820, 0x18828, 0x18830, 0x18838, 0x18840, 0x18848, 0x18850, 0x18858, 0x18860, 0x18868, 0x18870, 0x18878, 0x18880, 0x18888, 0x18890, 0x18898, 0x188a0, 0x188a8, 0x188b0, 0x188b8, 0x188c0, 0x188c8, 0x188d0, 0x188d8, 0x188e0, 0x188e8, 0x188f0, 0x188f8, 0x18900, 0x18908, 0x18910, 0x18918, 0x18920, 0x18928, 0x18930, 0x18938, 0x18940, 0x18948, 0x18950, 0x18958, 0x18960, 0x18968, 0x18970, 0x18978, 0x18980, 0x18988, 0x18990, 0x18998, 0x189a0, 0x189a8, 0x189b0, 0x189b8, 0x189c0, 0x189c8, 0x189d0, 0x189d8, 0x189e0, 0x189e8, 0x189f0, 0x189f8, 0x18a00, 0x18a08, 0x18a10, 0x18a18, 0x18a20, 0x18a28, 0x18a30, 0x18a38, 0x18a40, 0x18a48, 0x18a50, 0x18a58, 0x18a60, 0x18a68, 0x18a70, 0x18a78, 0x18a80, 0x18a88, 0x18a90, 0x18a98, 0x18aa0, 0x18aa8, 0x18ab0, 0x18ab8, 0x18ac0, 0x18ac8, 0x18ad0, 0x18ad8, 0x18ae0, 0x18ae8, 0x18af0, 0x18af8, 0x18b00, 0x18b08, 0x18b10, 0x18b18, 0x18b20, 0x18b28, 0x18b30, 0x18b38, 0x18b40, 0x18b48, 0x18b50, 0x18b58, 0x18b60, 0x18b68, 0x18b70, 0x18b78, 0x18b80, 0x18b88, 0x18b90, 0x18b98, 0x18ba0, 0x18ba8, 0x18bb0, 0x18bb8, 0x18bc0, 0x18bc8, 0x18bd0, 0x18bd8, 0x18be0, 0x18be8, 0x18bf0, 0x18bf8, 0x18c00, 0x18c08, 0x18c10, 0x18c18, 0x18c20, 0x18c28, 0x18c30, 0x18c38, 0x18c40, 0x18c48, 0x18c50, 0x18c58, 0x18c60, 0x18c68, 0x18c70, 0x18c78, 0x18c80, 0x18c88, 0x18c90, 0x18c98, 0x18ca0, 0x18ca8, 0x18cb0, 0x18cb8, 0x18cc0, 0x18cc8, 0x18cd0, 0x18cd8, 0x18ce0, 0x18ce8, 0x18cf0, 0x18cf8, 0x18d00, 0x18d08, 0x18d10, 0x18d18, 0x18d20, 0x18d28, 0x18d30, 0x18d38, 0x18d40, 0x18d48, 0x18d50, 0x18d58, 0x18d60, 0x18d68, 0x18d70, 0x18d78, 0x18d80, 0x18d88, 0x18d90, 0x18d98, 0x18da0, 0x18da8, 0x18db0, 0x18db8, 0x18dc0, 0x18dc8, 0x18dd0, 0x18dd8, 0x18de0, 0x18de8, 0x18df0, 0x18df8, 0x18e00, 0x18e08, 0x18e10, 0x18e18, 0x18e20, 0x18e28, 0x18e30, 0x18e38, 0x18e40, 0x18e48, 0x18e50, 0x18e58, 0x18e60, 0x18e68, 0x18e70, 0x18e78, 0x18e80, 0x18e88, 0x18e90, 0x18e98, 0x18ea0, 0x18ea8, 0x18eb0, 0x18eb8, 0x18ec0, 0x18ec8, 0x18ed0, 0x18ed8, 0x18ee0, 0x18ee8, 0x18ef0, 0x18ef8, 0x18f00, 0x18f08, 0x18f10, 0x18f18, 0x18f20, 0x18f28, 0x18f30, 0x18f38, 0x18f40, 0x18f48, 0x18f50, 0x18f58, 0x18f60, 0x18f68, 0x18f70, 0x18f78, 0x18f80, 0x18f88, 0x18f90, 0x18f98, 0x18fa0, 0x18fa8, 0x18fb0, 0x18fb8, 0x18fc0, 0x18fc8};
with open("got_addr.txt") as f:
    #lines = [line.rstrip() for line in f]
    for line in f:
        argv = line.split()
        #print(argv[0].split('_')[1], end=', ')
        print("0x"+argv[1], end=', ')
        #exit(0)
