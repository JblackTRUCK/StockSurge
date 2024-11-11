// Handle deposit and withdrawal
const cashBalanceElement = document.getElementById('cash-balance');
let cashBalance = parseFloat(cashBalanceElement.textContent); // Assume this balance is fetched from backend

// Handle deposit
document.getElementById('deposit-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const depositAmount = parseFloat(document.getElementById('deposit-amount').value);
    if (depositAmount > 0) {
        cashBalance += depositAmount;
        cashBalanceElement.textContent = cashBalance.toFixed(2);
        alert('Deposit successful');
    }
});

// Handle withdrawal
document.getElementById('withdraw-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const withdrawAmount = parseFloat(document.getElementById('withdraw-amount').value);
    if (withdrawAmount > 0 && withdrawAmount <= cashBalance) {
        cashBalance -= withdrawAmount;
        cashBalanceElement.textContent = cashBalance.toFixed(2);
        alert('Withdrawal successful');
    } else {
        alert('Insufficient funds or invalid amount');
    }
});