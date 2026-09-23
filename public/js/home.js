const logOutBtnElem = document.getElementById('btn-signout');

logOutBtnElem.addEventListener('click', async () => {
    const response = await fetch('/users/logout', {
        method: 'POST'
    });

    if(response.ok) {
        window.location.href = '/login.html';
    }
});