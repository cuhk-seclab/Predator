<?php
$test1 = 1;
$test2 = 2;
function factorial($n) {
    // 条件语句
    if ($n <= 1) {
        return 1; //7  //+
    } else {
        return $n * factorial($n - 1); //8 //+
    }
}
$test3 = 3;
function checkEvenOrOdd($num) { //+
    // 条件语句
    if ($num % 2 == 0) {
        return "even"; //9 //+
    } else {
        return "odd"; //10
    }
}
$test4 =4;
?>