const signOutBtnElem = document.getElementById('btn-signout');

signOutBtnElem.addEventListener('click', async () => {
    const response = await fetch('/users/signout', {
        method: 'POST'
    });

    if(response.ok) {
        window.location.href = '/login.html';
    }
});