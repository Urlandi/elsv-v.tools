# -*- coding: utf-8 -*-
"""
Very simple RPSL import/export records decoder for finding peers ASn

Notes from RFC2622

<peering> - <as-expression> [<router-expression-1>] [at <router-expression-2>] | <peering-set-name>

where <as-expression> is an expression over AS numbers and AS sets
using operators AND, OR, and EXCEPT
. . .
         The binary "EXCEPT" operator is the set subtraction
operator and has the same precedence as the operator AND (it is
semantically equivalent to "AND NOT" combination).  That is "(AS1
OR AS2) EXCEPT AS2" equals "AS1"

If a <peering-set-name> is used, the peerings are listed in the
corresponding peering-set object.  Note that the peering-set
objects can be recursive.
---------------------------------------------------------------------
<import-factor> ::= from <peering-1> [action <action-1>]
                    . . .
                    from <peering-N> [action <action-N>]
                    accept <filter>;

<import-term> ::=  <import-factor> |
                   LEFT-BRACE
                   <import-factor>
                   . . .
                   <import-factor>
                   RIGHT-BRACE

<import-expression> ::= <import-term>                           |
                        <import-term> EXCEPT <import-expression> |
                        <import-term> REFINE <import-expression>

import|export: [protocol <protocol1>] [into <protocol2>]
               <import-expression>
---------------------------------------------------------------------
default: to <peering> [action <action>] [networks <filter>]
"""
