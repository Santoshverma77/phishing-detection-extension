const cells = document.querySelectorAll('.cell');
  const status = document.getElementById('status');
  let currentPlayer = 'X';
  let gameBoard = Array(9).fill('');
  let gameActive = true;

  const winningConditions = [
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    [0, 4, 8],
    [2, 4, 6]
  ];

  const handleCellClick = (e) => {
    const index = parseInt(e.target.dataset.index);

    if (gameBoard[index] === '' && gameActive) {
      gameBoard[index] = currentPlayer;
      e.target.textContent = currentPlayer;
      handleResultValidation();
    }
  };

  const handleResultValidation = () => {
    let roundWon = false;
    for (let i = 0; i <= 7; i++) {
      const winCondition = winningConditions[i];
      let a = gameBoard[winCondition[0]];
      let b = gameBoard[winCondition[1]];
      let c = gameBoard[winCondition[2]];
      if (a === '' || b === '' || c === '') {
        continue;
      }
      if (a === b && b === c) {
        roundWon = true;
        break;
      }
    }

    if (roundWon) {
      status.textContent = `${currentPlayer} wins!`;
      gameActive = false;
      return;
    }

    let roundDraw = !gameBoard.includes('');
    if (roundDraw) {
      status.textContent = 'Game ended in a draw!';
      gameActive = false;
      return;
    }

    currentPlayer = currentPlayer === 'X' ? 'O' : 'X';
    status.textContent = `${currentPlayer}'s turn`;
  };

  cells.forEach(cell => cell.addEventListener('click', handleCellClick));
