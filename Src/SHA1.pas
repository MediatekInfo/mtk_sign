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

const HC0=$67452301;
const HC1=$EFCDAB89;
const HC2=$98BADCFE;
const HC3=$10325476;
const HC4=$C3D2E1F0;

const K1=$5A827999;
const K2=$6ED9EBA1;
const K3=$8F1BBCDC;
const K4=$CA62C1D6;

procedure SHA1Work(Z: string);
var H0,H1,H2,H3,H4: integer;

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

function SHA1Padding(s: string; FS: integer):string;                          //добавление одного бита (1000000=128) и добавление нулей до кратности 64 байтам
var
size,i: integer;
begin
size := Length(s) * 8;                                                        //size - входной размер в битах
s := s + char(128);                                                           //добавление одного бита  (1000000=128)

while (Length(s) mod 64) <> 0 do s := s + #0;                                 //добавление нулей до кратности 64 байтам

if ((size mod 512) >= 448)                                                    //если хвост превышает 48 байт то добавить пустой блок из 64 нулей
   then begin
        s := s + #0;                                                          //добавление нулей до кратности 64
        while (Length(s) mod 64) <>0 do s := s + #0;
        end;

i := Length(s); size := FS * 8;
while size > 0 do                                                             //запись в конец строки её размер
  begin
  s[i] := char(byte(size));                                                   //получение младшего байта
  size := size shr 8;                                                         //сдвиг вправо на 8 бит - перенос старшего байта на место младшего
  i := i - 1;
  end;
Result := s;
end;

procedure SHA1Start(const S_IN: string);
var
A, B, C, D, E, TEMP: dword;
t, i: byte;
W: array[0..79] of dword;
begin

t := 1;
for i := 1 to ((Length(S_IN)) div 4) do
  begin
  W[i - 1] := (ord(S_IN[t]) shl 24) + (ord(S_IN[t + 1]) shl 16) + (ord(S_IN[t + 2]) shl 8) + ord(S_IN[t + 3]);
  t := t + 4;
  end;


for t := 16 to 79 do W[t] := ROL(W[t - 3] xor W[t - 8] xor W[t - 14] xor W[t - 16], 1);

A := H0;
B := H1;
C := H2;
D := H3;
E := H4;

for t := 0 to 19 do
  begin
  TEMP := ROL(A, 5) + ((B and C) or ((not B) and D)) + E + K1 + W[t];
  E := D; D := C; C := ROL(B, 30); B := A; A := TEMP;
  end;

for t := 20 to 39 do
  begin
  TEMP := ROL(A, 5) + (B xor C xor D) + E + K2 + W[t];
  E := D; D := C; C := ROL(B, 30); B := A; A := TEMP;
  end;

for t := 40 to 59 do
  begin
  TEMP := ROL(A, 5) + ((B and C) or (B and D) or (C and D)) + E + K3 + W[t];
  E := D;  D := C;  C := ROL(B, 30);  B := A;  A := TEMP;
  end;

for t := 60 to 79 do
  begin
  TEMP := ROL(A, 5) + (B xor C xor D) + E + K4 + W[t];
  E := D; D := C; C := ROL(B, 30); B := A; A := TEMP;
  end;

H0 := A + H0;
H1 := B + H1;
H2 := C + H2;
H3 := D + H3;
H4 := E + H4;
end;

procedure SHA1Work(Z: string);
var
s, s1: string;
i, L, FS: integer;
F: file;
n: integer;
Buf: array[1..65536] of char;
begin
s := '';

AssignFile(F, Z);
FileMode := FmOpenRead;
Reset(F, 1);
FS := FileSize(F);

SHA1Init();

repeat
  BlockRead(F, Buf, sizeOf(Buf), n);
  SetLength(s1, n);
  for i := 1 to n do s1[i] := Buf[i];

  s := s1;
  L := length(s1);
  if ((L < 65536) and (L > 0))
     then begin
          s1:= SHA1Padding(s, FS);
          i := 1;
          L := length(s1);
          while i < L do
            begin
            SHA1Start(copy(s1, i, 64));
            i := i + 64;
            end;
     end;

  if L = 65536
     then begin
          i := 1;
          L := length(s1);
          while i < L do
            begin
            SHA1Start(copy(s1, i, 64));
            i := i + 64;
            end;
          end;
  n := 0;
until n = 0;
CloseFile(F);

//Hout:=inttohex(H0,8)+' '+inttohex(H1,8)+' '+inttohex(H2,8)+' '+inttohex(H3,8)+' '+inttohex(H4,8);
end;

end.
