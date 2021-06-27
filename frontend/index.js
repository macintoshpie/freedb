const apiBaseUrl = `http://localhost:8000` 

let dbToken = null
const errorContainer = document.getElementById('error-container')
const tokenContainer = document.getElementById('db-token')
const queryInput = document.getElementById('query-input')
const queryResponseContainer = document.getElementById('query-response')

window.onload = () => {
    // setup the page
    document.getElementById('create-button').addEventListener('click', createDB)
    document.getElementById('query-button').addEventListener('click', queryDB)
}

const goToStep = (step) => {
    document.querySelectorAll('.step').forEach(elem => {
        if (elem.id === `step-${step}`) {
            elem.classList.add('active')
        } else {
            elem.classList.remove('active')
        }
    })
}

const createDB = () => {
    goToStep('creating')

    apiCreateDB()
        .then(res => {
            if (res.error) {
                console.error(res.error)
                errorContainer.innerText = res.message
                goToStep('error')
            } else {
                dbToken = res.token
                tokenContainer.innerText = dbToken
                goToStep('created')
            }
        })
}



const queryDB = () => {
    queryResponseContainer.classList.remove('error')
    queryResponseContainer.innerText = "Submitting query..."
    const query = queryInput.value
    apiQueryDB({ query, token: dbToken })
        .then(res => {
            if (res.error) {
                queryResponseContainer.innerText = res.error
                queryResponseContainer.classList.add('error')
            } else {
                queryResponseContainer.innerText = JSON.stringify(res, null, 2)
            }
        })
}

const apiCreateDB = () => {
    return fetch(`${apiBaseUrl}/db`, {
        headers: {
        'Content-Type': 'application/json',
        },
        method: 'POST',
    })
    .then(response => response.json())
    .catch(e => ({error: e, message: 'Failed to create db, please try again'}))
}

const apiQueryDB = ({ token, query }) => {
    return fetch(`${apiBaseUrl}/q`, {
        headers: {
        'Content-Type': 'application/json',
        },
        method: 'POST',
        body: JSON.stringify({
            token,
            query
        })
    })
    .then(response => response.json())
    .catch(e => ({error: e, message: 'Failed to query db, please try again'}))
}
