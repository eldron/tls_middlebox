        �  
E        ���������f+e�}�=��lN�\]d*            x��Vao�H��Ŕ���mZ5�N:�I��dCs9��{{�w�];���	'N%�`wޛ�fֳ>3�`�B��Pddيk�x�����a�A&i��L,E�䋘0�
�D���R@���Ehݝ������!3�5��C�i\<�Is&�5�V�d��p���EƸ F��f't,#�*���Ng�^[����YR-;�ߡ]��2�օ���L�E�a�Q=���M2��{>8~Ls�"�[g:Ϧp��;���5��;��q� �'J|Hj��^���1�Dr�X���J3���a)�Q	.���rEMa"��'<cUXTMQ�������g1�x��L)걡��l�����$��9�R�Rm�P&R�����bs8
T�->�l�B�oB����!�����m����=U�83��w�L�w4���=���� ��l?�1����Z���q0�o��4.�8'Ǎ����)�������|��@������-�s�6��?����΋ts���DKEȣ@���N���i��:��-:+���S�5w�1=:�ຟ^�u?U����S�����Ȏ����f{��7�s����Kv:䕸k�H�S\D˄��'�YI�*ͫ����NQq�X	���rգn%����vh��h��f���Z��΅��5S˘)�K�,������-�R���Y���n�v��T�ؼ��bՅ����R�@J]�+�ш�"o�=P���t�B�f��%M��2�a�1�Z����7��N����y���S��T�$|p�x�y�}3�g~�L}�U�Z���+y:�
Ҝ�Y�7E��?2Q�S�QK�����H����"������#�L#un�B��'+	��+.݄+.�bJz+�I��9ݨ�3h��z�y5sF�ܝ�\<����\�k�j;��mHr�-�#JRt1r���#�w���~*lk2�s��̣,*���^�+BM�?��~-v�{x�W���������    �     H  
�       8    �������)��}ki7J�r5�@Ɏ            x�c``�� ���i��
*���A��:A���)��\�.���n��
�
�EPq��t�Լ��4.. ��"    :     1  
D      9    ����lG>��N� ?�����0;�	              T  n   ifeq ($(OS_ARCH),BSD_OS)
  �  :        k     $  
>      I   ������D�gWP�	���߾d]�*�              �     ifeq ($(OS_ARCH),SINIX)
    �     $  
=      K   ����t������8~޴�@�{�C�U              �  �   ifeq ($(OS_ARCH),SCOOS)
    �     H  
z      \   �����Xn8=u��!�@c9H��NL            x�c``S` c�̴�B��x� gM���Ă���JM._�Pg7�x[��"��^rZ:Wj^Jf d�l    �     E  
�      �   ����C
�GJ&�i���ˈ1䭒p              �  �   9ifeq ($(OS_ARCH),NetBSD)
MDCPUCFG_H = _netbsd.cfg
endif

    @     A  
�      �   ����\�S��ǘ����Kb���              �  �   5ifeq ($(OS_ARCH),dgux)
MDCPUCFG_H = _dgux.cfg
endif

    �     #  
�      �   ����Y
�+�1��ce�itwi              �  �   ifeq ($(OS_ARCH),DGUX)
    �     �  �      �   ����
�RJ��#��s>�J�@            x�c``c``�e``�LK-T�P�v�73��Q0���uquvs��P�U��,ʬ03�KNK�J�)N�"kl��K�L�b``9��0������=4u�R�]Э�
'� �4�U���scFA)7�dQ� V�C    +     I  �   	  A   	����'�l�n���+��;���ϡ              E  E   =ifeq ($(OS_ARCH),NEXTSTEP)
MDCPUCFG_H = _nextstep.cfg
endif

    t     $  �   
  D   
�����t�k��oM$O�@���I�X�              �     ifeq ($(OS_TARGET),OS2)
    �     ?       J   �������w
rd�.U��?�7���              �  �   3ifeq ($(OS_ARCH),QNX)
MDCPUCFG_H = _qnx.cfg
endif

    �     A  ;     �   �������#�SC�_���]��              �  �   5ifeq ($(OS_ARCH),BeOS)
MDCPUCFG_H = _beos.cfg
endif

         N  s     �   ����Ě�Y�G�ZHl%Eu����̿�            x�c``)```ic``��LK-T�P�v�73��1���uquvs��P�U�O̬03�KNK�J�)NŔ46�H�d�q ��s    f     K  s     4   ����uؘ>o�䒕D?�Z�@�1�               I   �   ?# Version 1.1 (the "NPL"); you may not use this file except in
    �     �       b   �����Q�w��Eq_��d=spRv            x�}��N�@�ǅƗ�I���TLlh�օRa��2@|�`����l���K!�����7X�'��]�N\3�^$6]���>��N#�#���/���-e2�RBN0����6�(�3!�ؠ�٦SL��1pQ0�V����PV=s �v<�Ui�]C.5�s�
o���	�]�<��*jSCp<b����n�������!B���~��F$����Z��S���rٞTuSw/Z��R��&1�I������z>    �     /  �        ����f�J��0�]~�V��^y��U              	�  	�   export:: $(MDCPUCFG_H)
  
z  
�        �     E  �     �   ����`z�;��kG��8tX	�/Z E              �     9	  ln -fs ../../../nsprpub/pr/include/md/$(MDCPUCFG_H) \
    	!     ?  �     �   �������N9�}' �:y�B�Og�              	n  	n   3ifeq ($(OS_ARCH),NTO)
MDCPUCFG_H = _nto.cfg
endif

    	`     $  �     �   ����eJ�^�H�\a5!f����m              	n  	�   ifeq ($(OS_TARGET),NTO)
    	�        �     �   ����\;5R�g?�QO@���fK,�                	�     �  \     /   ����F4��O��� �Vg��|�`#            x�}�;�@E_��l��DH�` ~
��Uo`�0�3��\�;����T����'t�PpEW�-{�f�`鸛��q9�?� ����f"T�1J�.�ĵ&�&'�B
�Ir4%eC.��t�[�X�V���e��h��B%�Nɷ�ul�|qZ:���Tu�3/g=�ZC㹺����_�� L{^��G�    
;        \     3   ������A0V�%�s�ƽHݛ�1�                
;     t  �     T   ����r��������S�?U���&�f            x�c``Y� ���i��
*����af�:��\�.���n��
�
��F�yfz�i�\�9ũ\@�G ��-5/%3(�.�@�0d#�L�X���X�Ylf�0�c#�� G�.h    
�     e  "     �   ����BF��'�`?���|^jX>��            x�c`��` c�̴�B��̜��"���#=C��p|����c����&P�33����r��8�:���{(�*ė�eV�'���%��s��d�q ~�         E          ����ypoo9%�=E���!}�%�q              �  )      S  S   -
ifeq ($(OS_ARCH),OS2)
MDCPUCFG_H = _os2.cfg
    Y    �       �   ��������b<�<p�2����o�            x��T�n1]�~�(�4RHڊK�)JE�i��T=z��� �^lo��_��ć q�{7$�"�Uvg޼���I?�G�3I�}��c���h��;0�99X�B���G�����gRJ��Lɣc�D�>�ud4�u��$T��/��kؘVb�x(�������LbU(Z"T��8���}aR/�Vpu����W�C�}q��UU�]�l��.{�'�����$Ͽ$ɋ��03_�9o)-=fP��&s�/`�BC�?���YR��u�n8{s;���t���������n8�� � �Ň¢c�-7S��Yf��&�
�� 	J�e)�K�F�I/���2�:E+�³��1�.���|�=����ɢ�P6F�(x�Ғ�0\j�%t{�CM���
רL�#bT����q���V�&�P[�t&�֯�E�M7;.�T"@��:�dІ���W/�OOOwu���W�1��OSth�lw�i���'j�k_�/�ʳ���7�(���IL1dy/0!�hWn�����Q�es�}y�-�>]n�K���ɨ��}�r�9H��t֬�E���Q4J$)R=#�<��.2a'RN�1\�E���a��R���h�����F��^�E����0BkB�]D�'�w�����>���d� �����B���ی(/p;��2���]"̍}�4#��n��J�1}�Uvfe&*��C����2͂8&��?����f�0>��7$���    :     �       �   ������f�ǎ ��|I��@�            x�c``|���$���`������_�������������Y�P�K-)NN,HU�/*IL�IU*�+��MU�����2�orQ�-���Q��ᬩ`hii�kd``�0�9?7�4/39�$3?��-*�/s�sr� ��-W    �    K  
     �   ����}XS�@���,e9Y<�Lf            x����n�@�#!�Dy�Q�C"��*�@�(QiD�FIJU8����Y��]������3���8rGB��8i���6�(�g�����K��߷Z��)�ʣ�t~*$B"0�������B��qf�D
}�Q9$�K�Nh{�ԋ�j4�WOa�s�����;���G�A(�s�)��s��f�~ pv��τF�f�tU̓~�i��|>2�VH�mӐ�a��>��N�#��ya-�[1�=Ɛ�����$WLA�=�ި
�ۡ�������N��a;�����3xы�;�䂐�0-ւ(b�qӊ0�^7v�Hh���4g)B�gh�P)X�N�:L� E&<�jw=5a�eN�J�����e{Jx�$tq�R*ߜ�����90;:�r%�e���F��]e���5�Ȋ%M��mw�7���P�4`��|r]q+�-%W��2D�vFk���ޣ_�^Xޮ��Ѹ��7`7���}خu;�������=	�ec,l������6����oQ��r��$��zM� �r6�������^���I�H�(��E��4�[���(��N�%7pe�(��������lS�        �       �   ����Փ�緑�k!�!({?��4            x��T�n�@5�S�b�^)8mO���T��4������z/Z��u��_��/H|��ٵCZ!|��y��̛����h^��(z�޿�a�#p�*gAg�ra!�[%��;p��������J��G�0�E���
��4>����'��[��

��T����ҁPD�(�`�#���^�}��(�QtI_!��s�;W^u]�E�6�f5��MG��{��E���Bg��"Sa�I�0�J�h0��~ �d
:��/:�0+l����7�K������n��pz���> 	"X|(Zj��d��b��`��D.2�A2���
a��h�P+J7b��ĘJA�B8���)��b��1�P�PL�H�A������3mKh��J9Q t��ټ��?V�	J��5J]R���g����8�EQ)�[~#mJm�G�f��2��d�#�G �M�QN��߼>;99�����PJ7͚�E���7�Fd�0Vm��w��JG=�tҸ�yϯ��c���{��~DS�mg���p�
5�Y�'+sFv�SZ�B�\�&�^�/E��g��Hi�Z� s[`6	�b%����yo)됥M�����u��,lc-l�w�I�밓:��n���Jn��u(�s ��v�X�=o}_ �?�C�%����f����$�F����fy��_,%�_��&!n��@3���6��&���OHѮY��B�'c��t!�Y
�	Axk����Zh���Zȗ�n��    �    �  #     �   �����Z��>%_���hA�4)�J            x�}T�n�@Bj	��1*�*U��z����H�(?T=U���Yj�Z������;7� ��\��H\�1�����QF��~��7?v����zP�C���� XfU¬�,��j��;�P��		�%p%Ce=���`2��eQZ*;r80�`��k����>Z�Y�0�f����A�y��%a�ہz�������*��-A*��k�x�1� $�s���`�#,���Ɇ=�d�f�Q���Z@�Y��[�>���b�%ꍈc�)�t�;ԣ�d?Ⱦ�`�B��K��Z̲�k�PoI��K��I�6��Waƌ0۔�;��8n�F�������n��HU%^�5V��+���1�:ф�LlR�"���LF�"u�Z
�ќ��d �H���*i�TMެ�ҟ�ʝ�{YN�+�,��c�R��G�U��ֽ016U�d��L�T:U��CS*]���b�h�6�A�-��e!�Mv���]!n�n�1����e��9����J�H���{z4h����Igk<�/��U��<��s��]9��Kb���z��r�����(?z�Y��ż����h��q���X�p����u���A��#�q��oTo��,F��vDH
a:n�6��A�M��+�re B���?!9�ٷ�q�}i��֣z�?�4z=�$���KV�]:�Tb���/|-��j�̓���_��o��h�