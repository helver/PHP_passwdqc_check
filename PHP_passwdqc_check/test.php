<?
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.

// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
// Copyright (c) 2013 by Eric Helvey
//

// Commandline bulk password strength tester.
// Invocation:
// php test.php < newlist
// echo "february3M" | php test.php

  $debug = 0;
  include_once("PasswordHash.inc");

  $params = array(
    "min" => array("disabled", 24, 11, 8, 7),
    "max" => 40,
    "passphrase" => 3,
    "match" => 4,
    "similar" => "deny",
    "random" => 47,
    "enforce" => "everyone",
    "retry" => 3,
  );

  setLocale(LC_CTYPE, 'en_US.UTF-8');
  $xx = new PasswordStrengthTest(array("debug" => $debug));

  #$xx->_passwdqc_wordset_4k = array('asset');

  $count = 0;
  while($line = fgets(STDIN)) {
    $line = trim($line);
    $errors = $xx->passwdqc_check($params, $line, "", "");

    if(!$errors) {
      print "OK: $line\n";
    } else {
      print "Bad passphrase ($errors): $line\n";
    }

    if($count >= 1000000) {
      exit();
    }
    $count++;
  }

?>
