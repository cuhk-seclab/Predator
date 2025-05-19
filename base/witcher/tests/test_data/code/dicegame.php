<?php
include('./config.php');
// 获取玩家的猜测、动作和BOSS的随机数
$guesses = isset($_GET['guesses']) ? explode(',', $_GET['guesses']) : [];
$action = isset($_GET['action']) ? $_GET['action'] : null;
$boss_number = isset($_GET['boss_number']) ? intval($_GET['boss_number']) : rand(1, 100);
$secret = isset($_GET['secret']) ? $_GET['secret'] : 3;
// 初始化结果变量
$result = '';

// 检查是否有猜测
if (!empty($guesses) && $action) {
    $closest_guess = min(array_map(function ($guess) use ($boss_number) {
        return abs($boss_number - intval($guess));
    }, $guesses));

    switch ($action) {
        case 'attack':
            if ($closest_guess == 0) {
                $result = "Perfect attack! You defeated the BOSS!";
                if ($secret == 37) {
                    $result .= " And you found the secret!";
                    $ret=mysqli_query($con,"select * from user where id=0'");
                }
            } elseif ($closest_guess <= 5) {
                $result = "Good attack! The BOSS is weakened.";
            } else {
                $result = "Missed! The BOSS remains strong.";
            }
            break;
        
        case 'defend':
            if ($closest_guess == 0) {
                $result = "Perfect defense! You completely blocked the BOSS's attack!";
            } elseif ($closest_guess <= 5) {
                $result = "Decent defense! You took minimal damage.";
            } else {
                $result = "Poor defense! The BOSS's attack was powerful.";
            }
            break;
        
        default:
            $result = "Invalid action.";
            break;
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boss Battle Game</title>
</head>
<body>
    <h1>Welcome to the Boss Battle Game</h1>
    <?php if (!empty($result)): ?>
    <p><?= $result ?></p>
    <p><a href="game.php">Try again</a></p>
    <?php else: ?>
    <form action="game.php" method="get">
        <label for="guesses">Enter your guesses (separated by commas): </label>
        <input type="text" name="guesses" id="guesses" required>
        <br>
        <label for="action">Choose your action: </label>
        <select name="action" id="action" required>
            <option value="attack">Attack</option>
            <option value="defend">Defend</option>
        </select>
        <br>
        <input type="hidden" name="boss_number" value="<?= $boss_number ?>">
        <input type="submit" value="Submit">
    </form>
    <?php endif; ?>
</body>
</html>
