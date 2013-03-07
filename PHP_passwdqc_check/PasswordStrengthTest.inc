<?php
// Adapted from passwdqc_check.c by Solar Designer
// http://http://www.openwall.com/passwdqc/
//
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
// Copyright (c) 2000-2002,2010 by Solar Designer.

class PasswordStrengthTest
{

  private $constants = array(
      "F_ENFORCE_MASK" => 0x00000003,
      "F_ENFORCE_USERS" => 0x00000001,
      "F_ENFORCE_ROOT" => 0x00000002,
      "F_ENFORCE_EVERYONE" => 0x00000003,
      "F_NON_UNIX" => 0x00000004,
      "F_ASK_OLDAUTHTOK_MASK" => 0x00000030,
      "F_ASK_OLDAUTHTOK_PRELIM" => 0x00000010,
      "F_ASK_OLDAUTHTOK_UPDATE" => 0x00000020,
      "F_CHECK_OLDAUTHTOK" => 0x00000040,
      "F_USE_FIRST_PASS" => 0x00000100,
      "F_USE_AUTHTOK" => 0x00000200,
  );

  private $reasons = array(
      "REASON_ERROR" => "check failed",
      "REASON_SAME" => "is the same as the old one",
      "REASON_SIMILAR" => "is based on the old one",
      "REASON_SHORT" => "too short",
      "REASON_LONG" => "too long",
      "REASON_SIMPLESHORT" => "not enough different characters or classes for this length",
      "REASON_SIMPLE" => "not enough different characters or classes",
      "REASON_PERSONAL" => "based on personal login information",
      "REASON_WORD" => "based on a dictionary word and not a passphrase",
      "REASON_SEQ" => "based on a common sequence of characters and not a passphrase",
  );

  /*
   * Common sequences of characters.
   * We don't need to list any of the characters in reverse order because the
   * code checks the new password in both "unified" and "unified and reversed"
   * form against these strings (unifying them first indeed).  We also don't
   * have to include common repeats of characters (e.g., "777", "!!!", "1000")
   * because these are often taken care of by the requirement on the number of
   * different characters.
   */
  private $seq = array(
    "0123456789",
    "`1234567890-=",
    "~!@#$%^&*()_+",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop[]\\asdfghjkl;'zxcvbnm,./",
    "qwertyuiop{}|asdfghjkl:\"zxcvbnm<>?",
    "qwertyuiopasdfghjklzxcvbnm",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-['=]\\",
    "qazwsxedcrfvtgbyhnujmikolp",
  );

  private $FIXED_BITS = 15;
  private $debug = 0;



  function __construct($args_array=null)
  {
    foreach($args_array as $k=>$v) {
      $this->{$k} = $v;
    }
    include_once("wordset_4k.inc");
    if(isset($this->debug) && $this->debug >= 6) {
      $this->_passwdqc_wordset_4k = array_slice($_passwdqc_wordset_4k, 0, 10);
    } else {
      $this->_passwdqc_wordset_4k = $_passwdqc_wordset_4k;
    }
  }



  private function isAscii($str) {
    if($this->debug >= 6) { print("Entering isAscii for $str<br>\n"); }
    return mb_check_encoding($str, 'ASCII');
  }



  private function mb_str_split($str) {
    return preg_split('/(?<!^)(?!$)/u', $str);
  }



  private function mb_strncmp($s1, $s2, $len=null)
  {
    if(!is_null($len)) {
      $s1a = mb_substr($s1, 0, $len);
      $s2a = mb_substr($s2, 0, $len);
    } else {
      $s1a = $s1;
      $s2a = $s2;
    }

    if($this->debug >= 5) { print("s1a: $s1a ; s2a: $s2a<br>\n"); }

    return strcmp(
      iconv('UTF-8', 'ISO-8859-1//TRANSLIT', $s1a),
      iconv('UTF-8', 'ISO-8859-1//TRANSLIT', $s2a));
  }



  /*
   * Calculates the expected number of different characters for a random
   * password of a given length.  The result is rounded down.  We use this
   * with the _requested_ minimum length (so longer passwords don't have
   * to meet this strict requirement for their length).
   */
  private function expected_different($charset, $length)
  {
    if($this->debug >= 5) { print("Entering expected_different for $charset and $length<br>\n"); }
    if($length <= 0) {
      if($this->debug >= 5) { print("Returning 0 from expected_different<br>\n"); }
      return 0;
    }

    $x = (($charset - 1) << $this->FIXED_BITS) / $charset;
    $y = $x;
    while(--$length > 0) {
      $y = ($y * $x) >> $this->FIXED_BITS;
    }
    $z = $charset * ((1 << $this->FIXED_BITS) - $y);

    if($this->debug >= 5) { printf("Returning %d from expected_different<br>\n", ($z >> $this->FIXED_BITS)); }
    return ($z >> $this->FIXED_BITS);
  }



  /*
   * A password is too simple if it is too short for its class, or doesn't
   * contain enough different characters for its class, or doesn't contain
   * enough words for a passphrase.
   *
   * The bias may be positive or negative.  It is added to the length,
   * except that a negative bias is not considered in the passphrase
   * length check because a passphrase is expected to contain words.
   * The bias does not apply to the number of different characters; the
   * actual number is used in all checks.
   */
  private function is_simple($params, $newpass, $bias)
  {
    if($this->debug >= 5) { print("Entering is_simple for $newpass and $bias<br>\n"); }
    $length = $classes = $words = $chars = 0;
    $digits = $lowers = $uppers = $others = $unknowns = 0;
    $p = ' ';


    foreach($this->mb_str_split($newpass) as $c) {
      $length++;

      if(!$this->isAscii($c)) {
        $unknowns++;
      } elseif(ctype_digit($c)) {
        $digits++;
      } elseif(ctype_lower($c)) {
        $lowers++;
      } elseif(ctype_upper($c)) {
        $uppers++;
      } else {
        $others++;
      }

      /* A word starts when a letter follows a non-letter or when a non-ASCII
       * character follows a space character.  We treat all non-ASCII characters
       * as non-spaces, which is not entirely correct (there's the non-breaking
       * space character at 0xa0, 0x9a, or 0xff), but it should not hurt. */
      if($this->isAscii($p)) {
        if($this->isAscii($c)) {
          if(ctype_alpha($c) && !ctype_alpha($p)) {
            $words++;
          }
        } elseif(ctype_space($p)) {
          $words++;
        }
      }
      $p = $c;

      /* Count this character just once: when we're not going to see it anymore */
      if (mb_strstr(mb_substr($newpass, $length), $c) === false) {
        if($this->debug >= 5) { printf("Counting $c because it's not in %s<br>\n", mb_substr($newpass, $length)); }
        $chars++;
      }
    }

    if($length <= 0) {
      if($this->debug >= 3) { print("Returning TRUE from is_simple length <= 0.<br>\n"); }
      return 1;
    }

    /* Upper case characters and digits used in common ways don't increase the
     * strength of a password */
    $c = mb_substr($newpass, 0, 1);
    if($uppers && $this->isAscii($c) && ctype_upper($c)) {
      $uppers--;
    }

    $c = mb_substr($newpass, ($length - 1), 1);
    if ($digits && $this->isAscii($c) && ctype_digit($c)) {
      $digits--;
    }

    /* Count the number of different character classes we've seen.  We assume
     * that there are no non-ASCII characters for digits. */
    $classes = 0;
    if($digits > 0) { $classes++; }
    if($lowers) { $classes++; }
    if($uppers) { $classes++; }
    if($others) { $classes++; }
    if($unknowns > 0 && $classes <= 1 && (($classes <= 0) || ($digits > 0) || ($words >= 2))) { $classes++; }

    if($this->debug >= 5) { printf("classes: %d ; digits: %d ; lowers: %d ; uppers: %d ; others: %d ; unkonwns: %d ; words: %d ; chars: %d ; length: %d.<br>\n", $classes, $digits, $lowers, $uppers, $others, $unknowns, $words, $chars, $length); }
    for($i = $classes; $i > 0; $i--) {
      switch($i) {
        case 1:
          # Only one type of character.  If the min password size for a single
          # character class is not a number, then we're going to assume that
          # we should disallow any passwords with only one characer class.
          if(   is_numeric($params["min"][0])
             && (($length + $bias) >= $params["min"][0])
             && ($chars >= ($this->expected_different(10, $params["min"][0]) - 1))) {
            if($this->debug >= 5) {
              printf("%d + %d >= %s<Br>\n", $length, $bias, $params["min"][0]);
              printf("%d >= %d<Br>\n", $chars, $this->expected_different(10, $params["min"][0]) - 1);
            }
            if($this->debug >= 3) { print("Returning FALSE from is_simple case 1.<br>\n"); }
            return 0;
          } else {
            if($this->debug >= 3) { print("Returning TRUE from is_simple case 1.<br>\n"); }
            return 1;
          }
          break;

        case 2:
          # Two types of characters.  If the min password size for two
          # character classes is not a number, then we're going to assume that
          # we should disallow any passwords with only two characer classes.
          if(   is_numeric($params["min"][1])
             && (($length + $bias) >= $params["min"][1])
             && ($chars >= ($this->expected_different(36, $params["min"][1]) - 1))) {
            if($this->debug >= 3) { print("Returning FALSE from is_simple case 2a.<br>\n"); }
            return 0;
          } elseif(!isset($params["passphrase_words"]) || (!$params["passphrase_words"]) || ($words < $params["passphrase_words"])) {
            continue;
          } elseif(   (($length + ($bias > 0 ? $bias : 0)) >= $params["min"][2])
                   && ($chars >= ($this->expected_different(27, $params["min"][2]) - 1))) {
            if($this->debug >= 3) { print("Returning FALSE from is_simple case 2b.<br>\n"); }
            return 0;
          } else {
            continue;
          }
          break;

        case 3:
          # Three character classes.  Assumption will be that we most certainly
          # will have a number as the min length for a password comprised of 3
          # character classes.
          if(   (($length + $bias) >= $params["min"][3])
             && ($chars >= $this->expected_different(62, $params["min"][3]) - 1)) {
            if($this->debug >= 3) { print("Returning FALSE from is_simple case 3.<br>\n"); }
            return 0;
          } else {
            continue;
          }
          break;

        case 4:
          # Four character classes.  Assumption will be that we most certainly
          # will have a number as the min length for a password comprised of 4
          # character classes.
          if(   (($length + $bias) >= $params["min"][4])
             && ($chars >= $this->expected_different(95, $params["min"][4]) - 1)) {
            if($this->debug >= 3) { print("Returning FALSE from is_simple case 4.<br>\n"); }
            return 0;
          } else {
            continue;
          }
      }
    }

    if($this->debug >= 3) { print("Returning TRUE from is_simple.<br>\n"); }
    return 1;
  }



  private function unify($src)
  {
    if($this->debug >= 4) { print("Entering unify for $src<br>\n"); }

    $src = mb_strtolower($src);
    foreach($this->mb_str_split($src) as $c) {
      $unique_chars[$c] = true;
    }

    if($this->debug >= 5) { var_dump($unique_chars); print "<br>\n"; }

    $froms = array();
    $tos = array();

    foreach(array_keys($unique_chars) as $c) {
      if($this->debug >= 5) { print("Character: $c<br>\n"); }

      switch($c) {
        case 'a':
        case '@':
          $froms[] = "[a@]";
          $tos[] = "4";
          break;

        case 'e':
          $froms[] = "e";
          $tos[] = "3";
          break;

        /* Unfortunately, if we translate both 'i' and 'l' to '1', this would
         * associate these two letters with each other - e.g., "mile" would
         * match "MLLE", which is undesired.  To solve this, we'd need to test
         * different translations separately, which is not implemented yet. */
        case 'i':
        case '|':
          $froms[] = "[i\|]";
          $tos[] = "!";
          break;

        case 'l':
          $froms[] = "l";
          $tos[] = "1";
          break;

        case 'o':
          $froms[] = "o";
          $tos[] = "0";
          break;

        case 's':
        case '$':
          $froms[] = "[s\$]";
          $tos[] = "5";
          break;

        case 't':
        case '+':
          $froms[] = "[t\+]";
          $tos[] = "7";
          break;
      }
    }

    if($this->debug >= 5) {
      var_dump ($froms); print "<br>\n";
      var_dump ($tos); print "<br>\n";
    }

    $dst = $src;
    for($i = 0; $i < count($froms); $i++) {
      $dst = mb_ereg_replace($froms[$i], $tos[$i], $dst);
    }

    if($this->debug >= 4) { print("Leaving unify with $dst<br>\n"); }
    return $dst;
  }



  private function reverse($instr)
  {
    if($this->debug >= 5) { print("Entering reverse for $instr<br>\n"); }
    $ar = array();
    preg_match_all('/./us', $instr, $ar);
    $rtsni = join('', array_reverse($ar[0]));

    if($this->debug >= 5) { var_dump($ar); print "<br>\n"; }
    if($this->debug >= 4) { print("Leaving reverse with $rtsni<br>\n"); }
    return $rtsni;
  }



  /*
   * Needle is based on haystack if both contain a long enough common
   * substring and needle would be too simple for a password with the
   * substring either removed with partial length credit for it added
   * or partially discounted for the purpose of the length check.
   */
  private function is_based($params, $haystack, $needle, $original, $mode)
  {
    # Mode is 0x102, 0x101, 0x100, 0x002, 0x001, 0x000.
    if($this->debug >= 3) { print("Entering is_based for $haystack , $needle , $original and $mode<br>\n"); }
    if(!$params["match"]) { return 0; }
    if($params["match"] < 0) { return 1; }

    $worst_bias = 0;
    $length = mb_strlen($needle);
    $spin_on_haystack = true;

    for($i = 0; $i <= ($length - $params["match"]); $i++) {
      if($this->debug >= 5) { print("i - $i<br>\n"); }
      for($j = $params["match"]; ($i + $j) <= $length; $j++) {
        if($this->debug >= 5) { print("j - $j - ($i + $j) <= $length<br>\n"); }
        $bias = 0;
        $j1 = $j - 1;

        $q0 = mb_substr($needle, $i, 1);
        $q1 = mb_substr($needle, ($i + 1));

        if($this->debug >= 5) { print("needle - $needle ; q0 - $q0 ; q1 = $q1<br>\n"); }
        for($iter = 0; ($spin_on_haystack && ($iter < mb_strlen($haystack))); $iter++) {
          $p = mb_substr($haystack, $iter, 1);
          $prest = mb_substr($haystack, ($iter+1));

          if($this->debug >= 5) { print("p - $p ; prest = $prest<br>\n"); }
          if(($p == $q0) && !$this->mb_strncmp($prest, $q1, $j1)) {
            if($this->debug >= 5) {
              print("$p == $q0.  $prest == $q1 to length $j1<br>\n");
              print("mode - $mode ; bitwise against 0xff - " . ($mode & 0xff) . "<br>\n");
              print("mode - $mode ; bitwise against 0x100 - " . ($mode & 0x100) . "<br>\n");
            }

            # If $mode & 0xff is zero, that means we were called directly and not
            # by is_word_based.
            if(($mode & 0xff) == 0) {
              if($this->debug >= 5) { print("Called directly - mode $mode<br>\n"); }
              if(($mode & 0x100) == 0) {
                if($this->debug >= 5) { print("String is not reversed.<br>\n"); }
                $pos = $i;
              } else {
                if($this->debug >= 5) { print("String is reversed.<br>\n"); }
                $pos = $length - ($i + $j);
              }

              $scratch = mb_substr($original, 0, $pos) . mb_substr($original, ($pos + $j), ($length + 1 - ($pos + $j)));
              $bias = $params["match"] - 1;

              if($this->debug >= 5) { print("Scratch == $scratch<br>\n"); }
              if($this->is_simple($params, $scratch, $bias)) {
                if($this->debug >= 3) { print("Returning TRUE from is_based<br>\n"); }
                return 1;
              }
            } else {
              if($this->debug >= 5) { print("Called by is_word_based - mode $mode<br>\n"); }
              $bias = -1;

              if(($mode & 0xff) == 1) {
                if($this->debug >= 5) { print("Word list match - mode $mode<br>\n"); }
                if(($mode & 0x100) > 0) {
                  if($this->debug >= 5) { print("World list match reversed - mode $mode<br>\n"); }
                  $pos = $length - ($i + $j);
                  $end = $length - $i;
                } else {
                  if($this->debug >= 5) { print("Word list match not reversed - mode $mode<br>\n"); }
                  $pos = $i;
                  $end = $i + $j;
                }

                if($this->debug >= 5) {
                  print("pos - $pos ; end - $end<br>\n");
                  print("splitting string: " . mb_substr($original, $pos, ($end - $pos)) . "<br>\n");
                }

                foreach($this->mb_str_split(mb_substr($original, $pos, ($end - $pos))) as $c) {
                  if(!ctype_alpha($c)) {
                    if($j == $params["match"]) {
                      if($this->debug >= 5) { print("Found smallest substring match<Br>\n"); }

                      # Break out of mb, iter, and j loops
                      break 2;
                    } else {
                      $bias = 0;

                      # Break out of the mb loop
                      break;
                    }
                  }
                }
              }

              /* discount j - (match_length + bias) chars */
              $bias += $params["match"] - $j;
              /* bias <= -1 */
              if($this->debug >= 5) { print("Checking bias ($bias) versus worst bias ($worst_bias).<Br>\n"); }
              if($bias < $worst_bias) {
                if($this->is_simple($params, $original, $bias)) {
                  if($this->debug >= 3) { print("Returning TRUE from is_based<br>\n"); }
                  return 1;
                } else {
                  $worst_bias = $bias;
                }
              }
            }
          }
        }
        if(!$bias) {
          # Break out of the j loop
          if($this->debug >= 5) { print("Breaking out of the j loop.<Br>\n"); }
          break;
        }
      }
    }

    if($this->debug >= 3) { print("Returning FALSE from is_based<br>\n"); }
    return 0;
  }




  /*
   * This wordlist check is now the least important given the checks above
   * and the support for passphrases (which are based on dictionary words,
   * and checked by other means).  It is still useful to trap simple short
   * passwords (if short passwords are allowed) that are word-based, but
   * passed the other checks due to uncommon capitalization, digits, and
   * special characters.  We (mis)use the same set of words that are used
   * to generate random passwords.  This list is much smaller than those
   * used for password crackers, and it doesn't contain common passwords
   * that aren't short English words.  Perhaps support for large wordlists
   * should still be added, even though this is now of little importance.
   */
  private function is_word_based($params, $needle, $original, $is_reversed)
  {
    # Based on how we call stuff, $is_reversed will only ever be 0x000
    # or 0x100.
    if($this->debug >= 5) { print("Entering is_word_based for $needle , $original and $is_reversed<br>\n"); }
    if(!$params["match"]) { return; }

    # $mode is now 0x002 or 0x102.
    $mode = ($is_reversed | 2);

    foreach($this->seq as $v) {
      $unified = $this->unify($v);

      if(!$unified) {
        if($this->debug >= 3) { print("Failed to unify sequnce string: $v.<br>\n"); }
        return $this->reasons["REASON_ERROR"];
      }

      if($this->is_based($params, $unified, $needle, $original, $mode)) {
        if($this->debug >= 3) { print("Needle matched sequence: $v.<br>\n"); }
        return $this->reasons["REASON_SEQ"];
      }
    }

    # $mode is now 0x001 or 0x101.
    $mode = ($is_reversed | 1);
    $prev_word = "";

    foreach($this->_passwdqc_wordset_4k as $word) {
      if(mb_strlen($word) < $params["match"]) { continue; }
      if(!$this->mb_strncmp($word, $prev_word)) { continue; }

      $word = $this->unify($word);
      $prev_word = $word;

      if($this->is_based($params, $word, $needle, $original, $mode)) {
        if($this->debug >= 3) { print("Failing because of new is based on the word $word.<br>\n"); }
        return $this->reasons["REASON_WORD"];
      }
    }

    # $mode is now 0x002 or 0x102.
    $mode = ($is_reversed | 2);
    if($params["match"] <= 4) {
      for($i = 1900; $i <= 2039; $i++) {
        $word = sprintf("%u", $i);
        if($this->is_based($params, $word, $needle, $original, $mode)) {
          if($this->debug >= 3) { print("Failing because of new is based on the number $word.<br>\n"); }
          return $this->reasons["REASON_SEQ"];
        }
      }
    }

    return;
  }



  public function passwdqc_check($params, $newpass, $oldpass, $pw)
  {
    if($this->debug >= 4) { print("Entering passwdqc_check for $newpass and $oldpass<br>\n"); }

    $reason = $this->reasons["REASON_ERROR"];
    $done = false;

    if($this->debug >= 5) { print("About to check if old and new are the same.<br>\n"); }
    if($oldpass && !$this->mb_strncmp($oldpass, $newpass)) {
      $reason = $this->reasons["REASON_SAME"];
      if($this->debug >= 3) { print("Old and new are the same.<br>\n"); }
      $done = true;
    }

    $length = mb_strlen($newpass);

    if($this->debug >= 5) { print("About to check if new is too short.<br>\n"); }
    if(!$done) {
      if($length < $params["min"][4]) {
        $reason = $this->reasons["REASON_SHORT"];
        if($this->debug >= 3) { print("New is too short.<br>\n"); }
        $done = true;
      }
    }

    if($this->debug >= 5) { print("About to check if new is too long.<br>\n"); }
    if(!$done) {
      if($length > $params["max"]) {
        if($params["max"] == 8) {
          if($oldpass && !$this->mb_strncmp($oldpass, $newpass, 8)) {
            if($this->debug >= 3) { print("First 8 chars of new match old.<br>\n"); }
            $reason = $this->reasons["REASON_SAME"];
            $done = true;
          }
        } else {
          $reason = $this->reasons["REASON_LONG"];
          if($this->debug >= 3) { print("New is too long.<br>\n"); }
          $done = true;
        }
      }
    }

    if($this->debug >= 5) { print("About to check if new is too simple.<br>\n"); }
    if(!$done) {
      if($this->is_simple($params, $newpass, 0)) {
        $reason = $this->reasons["REASON_SIMPLE"];
        if(($length < $params["min"][1]) && ($params["min"][1] <= $params["max"])) {
          $reason = $this->reasons["REASON_SIMPLESHORT"];
          if($this->debug >= 3) { print("New is too simple to be that short.<br>\n"); }
        } else {
          if($this->debug >= 3) { print("New is too simple.<br>\n"); }
        }
        $done = true;
      }
    }

    if(!$done) {
      $u_newpass = $this->unify($newpass);
      if(!$u_newpass) {
        $done = true;
        if($this->debug >= 3) { print("Failing new unify.<br>\n"); }
      }
    }

    if(!$done) {
      $u_reversed = $this->reverse($u_newpass);
      if(!$u_reversed) {
        $done = true;
        if($this->debug >= 3) { print("Failing new reverse.<br>\n"); }
      }
    }

    if(!$done) {
      if($oldpass) {
        $u_oldpass = $this->unify($oldpass);
        if(!$u_oldpass) {
          $done = true;
          if($this->debug >= 3) { print("Failing old unify.<br>\n"); }
        }
      }
    }

    if(isset($pw) && is_array($pw)) {
      if(isset($pw["pw_name"]) && $pw["pw_name"] != "") {
        $u_name = $this->unify($pw["pw_name"]);
      } else {
        $u_name = true;
      }

      if(isset($pw["pw_gecos"]) && $pw["pw_gecos"] != "") {
        $u_gecos = $this->unify($pw["pw_gecos"]);
      } else {
        $u_gecos = true;
      }

      if(isset($pw["pw_dir"]) && $pw["pw_dir"] != "") {
        $u_dir = $this->unify($pw["pw_dir"]);
      } else {
        $u_dir = true;
      }

      if($this->debug >= 3) { printf("name: %s ; gecos: %s ; dir: %s<br>\n", $u_name, $u_gecos, $u_dir); }
      if(!$u_name || !$u_gecos || !$u_dir) {
        if($this->debug >= 3) { print("Failing because personal information can't be unified.<br>\n"); }
        $done = true;
      }
    }

    if($this->debug >= 5) { print("About to check if new is based on old.<br>\n"); }
    if(!$done && $oldpass && $params["similar_deny"]) {
      $base1 = $this->is_based($params, $u_oldpass, $u_newpass, $newpass, 0);
      $base2 = $this->is_based($params, $u_oldpass, $u_reversed, $newpass, 0x100);

      if($base1 || $base2) {
        $reason = $this->reasons["REASON_SIMILAR"];
        $done = true;
        if($this->debug >= 3) { print("Failing because new is based on old.<br>\n"); }
      }
    }

    if($this->debug >= 5) { print("About to check if new is based on personal information.<br>\n"); }
    if(!$done && isset($pw) && is_array($pw)) {
      if($u_name === true) {
        $tbased1 = false;
        $tbased2 = false;
      } else {
        $tbased1 = $this->is_based($params, $u_name, $u_newpass, $newpass, 0);
        $tbased2 = $this->is_based($params, $u_name, $u_reversed, $newpass, 0x100);
      }

      if($u_gecos === true) {
        $tbased3 = false;
        $tbased4 = false;
      } else {
        $tbased3 = $this->is_based($params, $u_gecos, $u_newpass, $newpass, 0);
        $tbased4 = $this->is_based($params, $u_gecos, $u_reversed, $newpass, 0x100);
      }

      if($u_dir === true) {
        $tbased5 = false;
        $tbased6 = false;
      } else {
        $tbased5 = $this->is_based($params, $u_dir, $u_newpass, $newpass, 0);
        $tbased6 = $this->is_based($params, $u_dir, $u_reversed, $newpass, 0x100);
      }

      if($tbased1 || $tbased2 || $tbased3 || $tbased4 || $tbased5 || $tbased6) {
        $reason = $this->reasons["REASON_PERSONAL"];
        $done = true;
        if($this->debug >= 3) { print("Failing because new is based on personal information.<br>\n"); }
      }
    }

    if($this->debug >= 5) { print("About to check if new is based on a word list entry.<br>\n"); }
    if(!$done) {
      if($this->debug >= 5) { print("Checking $u_newpass forward.<br>\n"); }
      $reason = $this->is_word_based($params, $u_newpass, $newpass, 0);
      if(!$reason) {
        if($this->debug >= 5) { print("Checking $u_reversed backwards.<br>\n"); }
        $reason = $this->is_word_based($params, $u_reversed, $newpass, 0x100);
      }
      if($reason) {
        if($this->debug >= 3) { print("Failing because new is based on a word list entry.<br>\n"); }
      }
    }

    return $reason;
  }

}
?>
