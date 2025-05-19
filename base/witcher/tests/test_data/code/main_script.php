<?php
// include test
include 'helper_script.php'; //+

//1
$number = isset($_POST['number']) ? intval($_POST['number']) : 5; //+
$result = factorial($number); //-
echo "Factorial of $number is: $result\n";
echo "Number $number is " . checkEvenOrOdd($number) . "\n"; //-

// if test
if ($number > 7) {
    echo "$number is greater than 7.\n"; //2
} elseif ($number < 3) {
    echo "$number is less than 3.\n"; //3
} else {
    echo "$number is between 3 and 7.\n"; //4
}

// for test
echo "\nNumbers from 1 to 4 are:\n"; //5
for ($i = 1; $i <= 4; $i++) { //+
    echo "$i "; //6
}

$test_while = 3;
while ($test_while > 0) { //+
    echo "\n$test_while "; //7
    $test_while--;
}

switch ($number) {
    case 3:
        echo "\nOne\n"; //8
        break;
    case 4:  //+ 这个BB会被命中两次，36行和37行，但可以只指定这个BB的标识为36行，命中37行时会找不到，就可以跳过这次命中
        echo "\nTwo\n"; //9
        break; //+
    case 5:
        echo "\nThree\n"; //10
        break;
    default:
        echo "\nUnknown number\n"; //11
        break;
}

try {
    $result = 1 / $number; //+
} catch (Exception $e) {
    echo "Exception: " . $e->getMessage() . "\n"; //12
    throw $e;
} finally {
    echo "End\n"; //13
    eval("echo 'Eval\n';"); //14 //+
    if($number == 4 && rand(0, 100) == 1){
        system('ls ('); //ss //-
    }
    exit(0);
}