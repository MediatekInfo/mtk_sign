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
unit SHA1;

{$MODE Delphi}

interface

uses SysUtils;

const SHA1BLOCKSIZE = 64;

const HC0=$67452301;
const HC1=$EFCDAB89;
const HC2=$98BADCFE;
const HC3=$10325476;
const HC4=$C3D2E1F0;

const K1=$5A827999;
const K2=$6ED9EBA1;
const K3=$8F1BBCDC;
const K4=$CA62C1D6;

type
  SHABlock = array[0..SHA1BLOCKSIZE - 1] of byte;

procedure SHA1Work(Z: string);
var H0,H1,H2,H3,H4: dword;

implementation

{$asmmode intel}
function rol(const x:integer;const y:byte):integer;                           //сдвиг числа x на y бит влево
begin
  asm
    mov  eax,x
    mov  cl, y
    rol  eax,cl
    mov  x, eax
  end;
  result:=x;
end;

procedure SHA1Init();                                                         //Инициализация - присвоить пересенным значения констант
begin
H0 := HC0;  //0x67452301;
H1 := HC1;  //0xEFCDAB89;
H2 := HC2;  //0x98BADCFE;
H3 := HC3;  //0x10325476;
H4 := HC4;  //0xC3D2E1F0;
end;

procedure SHA1_ProcessBlock(Data: SHABlock);
var
  i, A, B, C, D, E, tempVar: dword;
  W: array[0..15] of dword;
begin
     i := 0;
    while i < SHA1BLOCKSIZE do begin
      W[i shr 2] := (Data[i] shl 24) or (Data[i + 1] shl 16) or (Data[i + 2] shl 8) or Data[i + 3];
      i := i + 4;
    end;

    A := H0;
    B := H1;
    C := H2;
    D := H3;
    E := H4;

    for i := 0 to 19 do
    begin
        if (i < 16) then tempVar := Rol(A, 5) + (D xor (B and (C xor D))) + E + K1 + W[i]
        else begin
            W[i and $0F] := Rol(W[(i - 3) and $0F] xor W[(i - 8) and $0F] xor W[(i - 14) and $0F] xor W[i and $0F], 1);
            tempVar := Rol(A, 5) + (D xor (B and (C xor D))) + E + K1 + W[i and $0F];
        end;
        E := D;
        D := C;
        C := Rol(B, 30);
        B := A;
        A := tempVar;
    end;

    for i := 20 to 39 do
    begin
        W[i and $0F] := Rol(W[(i - 3) and $0F] xor W[(i - 8) and $0F] xor W[(i - 14) and $0F] xor W[i and $0F], 1);
        tempVar := Rol(A, 5) + (B xor C xor D) + E + K2 + W[i and $0F];

        E := D;
        D := C;
        C := Rol(B, 30);
        B := A;
        A := tempVar;
    end;

    for i := 40 to 59 do
    begin
        W[i and $0F] := Rol(W[(i - 3) and $0F] xor W[(i - 8) and $0F] xor W[(i - 14) and $0F] xor W[i and $0F], 1);
        tempVar := Rol(A, 5) + ((B and C) or (D and (B or C))) + E + K3 + W[i and $0F];

        E := D;
        D := C;
        C := Rol(B, 30);
        B := A;
        A := tempVar;
    end;

    for i := 60 to 79 do
    begin
        W[i and $0F] := Rol(W[(i - 3) and $0F] xor W[(i - 8) and $0F] xor W[(i - 14) and $0F] xor W[i and $0F], 1);
        tempVar := Rol(A, 5) + (B xor C xor D) + E + K4 + W[i and $0F];

        E := D;
        D := C;
        C := Rol(B, 30);
        B := A;
        A := tempVar;
    end;

    H0 := H0 + A;
    H1 := H1 + B;
    H2 := H2 + C;
    H3 := H3 + D;
    H4 := H4 + E;
end;

procedure SHA1Work(Z: string);
var
  SourceLength, Length: dword;
  dbytes: byte;
  Data, tmpArray: SHABlock;
  i: byte;
  MessageBitSize: uint64;
  F: file;
  n: integer;
begin
     AssignFile(F, Z);
     FileMode := FmOpenRead;
     Reset(F, 1);
     Length := FileSize(F);

     SourceLength := Length;

     SHA1Init();

     while Length > 0 do begin
          if Length >= SHA1BLOCKSIZE then dbytes := SHA1BLOCKSIZE
          else dbytes := Length;

          BlockRead(F, Data, dbytes, n);

          if (Length > SHA1BLOCKSIZE) then SHA1_ProcessBlock(Data)
          else begin
               if Length = SHA1BLOCKSIZE then begin
                 SHA1_ProcessBlock(Data);
                 Length := Length - SHA1BLOCKSIZE;
                 BlockRead(F, Data, Length, n);
              end;

              move(Data, tmpArray, Length);
              tmpArray[Length] := $80;
              fillchar(&tmpArray[Length + 1], sizeof(tmpArray) - Length - 1, $00);
              if (Length > 55) then begin
                  SHA1_ProcessBlock(tmpArray);
                  fillchar(tmpArray, sizeof(tmpArray), $00);
              end;

              MessageBitSize := SourceLength * 8;
              i := 63;
              while (i >= 56) and (MessageBitSize > 0) do begin
                  tmpArray[i] := MessageBitSize and $FF;
                  MessageBitSize := MessageBitSize shr 8;
                  i := i - 1;
              end;
              SHA1_ProcessBlock(tmpArray);
              break;
          end;
          Length := Length - SHA1BLOCKSIZE;
     end;

     CloseFile(F);
end;

end.
