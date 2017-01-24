/*
 * This file is part of Sibyl.
 * Copyright 2014 Camille MOUGEY <camille.mougey@cea.fr>
 *
 * Sibyl is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Sibyl is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Sibyl. If not, see <http://www.gnu.org/licenses/>.
 */

int isalnum(int c)
{
	return(((c>='a') && (c<='z')) || ((c>='A') && (c<='Z')) || ((c>='0') && (c<='9')));
}

int isalpha(int c)
{
	return((c >='a' && c <='z') || (c >='A' && c <='Z'));
}
int isascii(int c)
{
	return (c >= 0 && c< 128);
}
int isdigit (int c)
{
	return((c>='0') && (c<='9'));
}
int isblank(int c)
{
	return ((c == ' ') || (c == '\t'));
}
int iscntrl(int c)
{
	return((c==0x7F) || (c>=0 && c<=0x1F));
}
int islower(int c)
{
	return ((c>='a') && (c<='z'));
}
int isprint(int c)
{
	return(c>=0x20 && c<=0x7E);
}
int isgraph(int c)
{
	return(c>0x20 && c<=0x7E);
}
int ispunct(int c)
{
	return(isgraph(c) && !isalnum(c));
}
int isspace(int c)
{
	return ((c>=0x09 && c<=0x0D) || (c==0x20));
}
int isupper(int c)
{
	return ((c>='A') && (c<='Z'));
}
int isxdigit (int c)
{
	return(((c>='0') && (c<='9')) || ((c>='A') && (c<='F')) || ((c>='a') && (c<='f')) );
}


int main() {
	return 0;
}
