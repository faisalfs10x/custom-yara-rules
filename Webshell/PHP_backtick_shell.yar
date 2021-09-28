/*
   YARA Rule Set
   Author: faisalfs10x
   Date: 2021-09-27
   Identifier: Webshell
   Reference: https://www.php.net/manual/en/language.operators.execution.php
   MITRE ATT&CK: https://attack.mitre.org/techniques/T1505/003/

*/

/* Rule Set ----------------------------------------------------------------- */

rule PHP_backtick_shell {

   meta:
      description = "Detect PHP webshell using backtick operator"
      Author = "faisalfs10x"
      reference = "https://www.php.net/manual/en/language.operators.execution.php"
      date = "2021-09-27"
      
   strings:
      $tag = "<?php" nocase ascii
      
      $str1 = "`$" ascii
      $str2 = "`" ascii //backtick
      
      $x1 = "$_GET" fullword ascii
      $x2 = "$_POST" fullword ascii
      $x3 = "$_SERVER['HTTP" ascii //HTTP_USER_AGENT & HTTP_ACCEPT_LANGUAGE

   condition:
      $tag and 1 of ($str*) and 1 of ($x1,$x2,$x3)
      
}
