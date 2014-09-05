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
