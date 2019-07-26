{
This file is part of the mtk_sign project.

Copyright (C) 2019 AJScorp

This program is free software; you can redistribute it and/or modify 
it under the terms of the GNU General Public License as published by 
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, 
but WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
General Public License for more details.

You should have received a copy of the GNU General Public License 
along with this program; if not, write to the Free Software 
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA. 
}

program mtk_sign;

{$MODE Delphi}

{$APPTYPE CONSOLE}
uses
  SysUtils, Classes, SHA1;

var
  BinFile: string = '';
  BinStream: TFileStream = nil;
  Buf: array[0..0] of cardinal;
  HashBuf: array[0..35] of byte;

function StartUp: boolean;
var
parcnt: integer;
i: integer;
s: string;
begin
Result:=True;

parcnt:=ParamCount;
if parcnt=0 then exit;

for i:=0 to parcnt do
    begin
    s:=ParamStr(i);
    if pos('.BIN',Uppercase(s))<>0
       then begin
            BinFile:=s;
            continue;
            end;
    end;

  try
  BinStream:=TFileStream.Create(BinFile,fmOpenReadWrite);
  except
  writeln('Can not open file "'+BinFile+'"!');
  exit;
  end;

BinStream.Position:=0;

Result:=False;
end;

begin
writeln('+-----------------------------------------------------+');
if not StartUp
   then begin
        FillChar(HashBuf, sizeof(HashBuf), 0);
        BinStream.Position := BinStream.Size - $24;
        BinStream.Read(HashBuf, 4);
        if (HashBuf[0] = 0) and (HashBuf[1] = byte('D')) and (HashBuf[2] = byte('N')) and (HashBuf[3] = byte('E'))
           then begin
                //Already signed
                BinStream.Size := BinStream.Size - $24;
                BinStream.Position := 0;
           end;

        FillChar(HashBuf, sizeof(HashBuf), 0);
        HashBuf[1]  := byte('D'); HashBuf[2] := byte('N'); HashBuf[3] := byte('E');

        Buf[0]:= BinStream.Size + sizeof(HashBuf);
        BinStream.Position := $20;
        BinStream.Write(Buf, 4);

        BinStream.Position := BinStream.Size;
        BinStream.Write(HashBuf, 4);

        BinStream.Free; BinStream:=nil;

        FillChar(HashBuf, sizeof(HashBuf), 0);
        SHA1Work(BinFile);

        HashBuf[4]  := (H0 shr 24) and $FF;
        HashBuf[5]  := (H0 shr 16) and $FF;
        HashBuf[6]  := (H0 shr 8)  and $FF;
        HashBuf[7]  := (H0 shr 0)  and $FF;

        HashBuf[8]  := (H1 shr 24) and $FF;
        HashBuf[9]  := (H1 shr 16) and $FF;
        HashBuf[10] := (H1 shr 8)  and $FF;
        HashBuf[11] := (H1 shr 0)  and $FF;

        HashBuf[12] := (H2 shr 24) and $FF;
        HashBuf[13] := (H2 shr 16) and $FF;
        HashBuf[14] := (H2 shr 8)  and $FF;
        HashBuf[15] := (H2 shr 0)  and $FF;

        HashBuf[16] := (H3 shr 24) and $FF;
        HashBuf[17] := (H3 shr 16) and $FF;
        HashBuf[18] := (H3 shr 8)  and $FF;
        HashBuf[19] := (H3 shr 0)  and $FF;

        HashBuf[20] := (H4 shr 24) and $FF;
        HashBuf[21] := (H4 shr 16) and $FF;
        HashBuf[22] := (H4 shr 8)  and $FF;
        HashBuf[23] := (H4 shr 0)  and $FF;

        writeln('H0 = ' + IntToHEX(HashBuf[4], 2) + IntToHEX(HashBuf[5], 2) + IntToHEX(HashBuf[6], 2) + IntToHEX(HashBuf[7], 2));
        writeln('H1 = ' + IntToHEX(HashBuf[8], 2) + IntToHEX(HashBuf[9], 2) + IntToHEX(HashBuf[10], 2) + IntToHEX(HashBuf[11], 2));
        writeln('H2 = ' + IntToHEX(HashBuf[12], 2) + IntToHEX(HashBuf[13], 2) + IntToHEX(HashBuf[14], 2) + IntToHEX(HashBuf[15], 2));
        writeln('H3 = ' + IntToHEX(HashBuf[16], 2) + IntToHEX(HashBuf[17], 2) + IntToHEX(HashBuf[18], 2) + IntToHEX(HashBuf[19], 2));
        writeln('H4 = ' + IntToHEX(HashBuf[20], 2) + IntToHEX(HashBuf[21], 2) + IntToHEX(HashBuf[22], 2) + IntToHEX(HashBuf[23], 2));

  try
  BinStream:=TFileStream.Create(BinFile, fmOpenReadWrite);
  except
  writeln('Can not open file "'+BinFile+'"!');
  exit;
  end;
        BinStream.Position := BinStream.Size;
        BinStream.Write(HashBuf[4], sizeof(HashBuf) - 4);
        BinStream.Free; BinStream:=nil;

        writeln(BinFile + ' signed Ok');
        end
   else writeln('Some error...');
writeln('+-----------------------------------------------------+');
end.
