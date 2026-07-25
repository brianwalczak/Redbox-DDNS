const { rateLimit } = require('express-rate-limit');
const session = require('express-session');
const express = require('express');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const reserved = ['ddns', 'search'];
const app = express();
const PORT = 8080;

// Cloudflare API details
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CLOUDFLARE_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID;
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

const GENERAL_RATE_LIMIT = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    limit: 300, // 300 requests per IP per 24 hours (this is for the entire website, so just viewing the pages counts)
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: "It looks like you've reached the maximum requests. Please try again in 24 hours."
});

const LOGIN_RATE_LIMIT = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    limit: 30, // 30 logins per IP per 24 hours (we're being generous here, in case it fails sometimes)
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: "It looks like you've reached the maximum login attempts. Please try again in 24 hours."
});

const SIGNUP_RATE_LIMIT = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    limit: 5, // 5 signups per IP per 24 hours (we're being generous here, in case it fails sometimes)
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: "It looks like you've already activated a domain. Please try again in 24 hours."
});

const UPDATE_RATE_LIMIT = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    limit: 60, // 60 updates to domain per IP per 5 minutes (since Cloudflare imposes 1,200 requests per 5 minutes)
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: "It looks like you've reached the maximum updates, please try again in 5 minutes."
});

const usersFilePath = process.env.USERS_FILE ? process.env.USERS_FILE : path.join(__dirname, './users.json');
const hops = parseInt(process.env.PROXY_HOPS, 10);
app.use(express.static('public'));
app.set('trust proxy', isNaN(hops) ? 2 : hops);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

app.get('/health', (req, res) => {
    res.sendStatus(200);
});

app.use(GENERAL_RATE_LIMIT);
app.use(session({
    secret: process.env.SESSION_TOKEN,
    resave: false,
    saveUninitialized: true,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict',
        httpOnly: true
    }
}));

// Read users from users.json
async function readUsers() {
    const data = await fs.promises.readFile(usersFilePath, 'utf8');
    return JSON.parse(data);
}

// Save users to users.json
async function saveUsers(users) {
    await fs.promises.writeFile(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
}

// Create DNS record in Cloudflare
async function reserveDNS(subdomain) {
    const ip = "1.1.1.1";
    const proxied = false;

    try {
        const recordResponse = await axios.post(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records`, {
            type: 'A',
            name: `${subdomain}.redbox.my`,
            content: ip,
            ttl: 1,
            proxied: proxied,
            comment: 'This record was created with the Redbox.my website for dynamic DNS.',
        },
        {
            headers: {
                Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                'Content-Type': 'application/json',
            },
        });

        if (recordResponse.status === 200 && recordResponse.data.success) {
            return { ip, proxied };
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}

// Update DNS record in Cloudflare
async function updateDNS(subdomain, ip, proxying, type) {
    try {
        const recordResponse = await axios.get(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?name=${subdomain}.redbox.my`, {
            headers: {
                Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                'Content-Type': 'application/json',
            },
        });
        if(!recordResponse.status === 200 || !recordResponse.data.result.length > 0) return false;
        
        const recordId = recordResponse.data.result[0].id; // Get the record ID from Cloudflare
        const updateResponse = await axios.put(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${recordId}`, {
                type: type || 'A',
                name: `${subdomain}.redbox.my`,
                content: ip,
                ttl: 1,
                proxied: proxying,
                comment: 'This record was created with the Redbox.my website for dynamic DNS.',
        },
        {
            headers: {
                Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                'Content-Type': 'application/json',
            },
        });

        if (updateResponse.status === 200 && updateResponse.data.success) {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}

// Delete DNS record in Cloudflare
async function deleteDNS(subdomain) {
    try {
        const recordResponse = await axios.get(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?name=${subdomain}.redbox.my`, {
            headers: {
                Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                'Content-Type': 'application/json',
            },
        });
        if(!recordResponse.status === 200 || !recordResponse.data.result.length > 0) return false;
        
        const recordId = recordResponse.data.result[0].id; // Get the record ID from Cloudflare
        const deleteResponse = await axios.delete(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${recordId}`, {
            headers: {
                Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                'Content-Type': 'application/json',
            },
        });

        if (deleteResponse.status === 200 && deleteResponse.data.success) {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}

// Check if the subdomain is reserved w/ Cloudflare API
async function isReserved(subdomain) {
    try {
        const response = await axios.get(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?name=${subdomain}.redbox.my`, {
            headers: {
                Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                'Content-Type': 'application/json',
            },
        });

        if (response.data.result.length > 0) {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}

// Verify the reCAPTCHA response
async function verifyRecaptcha(recaptchaToken) {
    try {
        const { data } = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
            params: {
                secret: RECAPTCHA_SECRET_KEY,
                response: recaptchaToken
            }
        });

        return data.success;
    } catch (error) {
        console.error("reCAPTCHA verification failed:", error);
        return false;
    }
}

// Prevents logged-in users from accessing the login and signup pages
const rejectLoggedIn = (req, res, next) => {
    if (req.session.user) {
        return res.send('It looks like you already have an activated domain.');
    }
    next();
};

// Validate IP address or domain
function isIpOrDomain(input) {
    if (/https?:\/\//.test(input) || /\//.test(input)) {
        return 'Invalid';
    }
    
    const isIP = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(input) && input.split('.').every(octet => octet >= 0 && octet <= 255);
    
    const isDomain = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$/.test(input);
    
    return isIP ? 'ip' : isDomain ? 'domain' : false;
}

app.get('/', (req, res) => {
    res.redirect('/signup');
});

app.get('/login', (req, res) => {
    if(req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.render('login');
    }
});

app.get('/signup', (req, res) => {
    if(req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.render('signup');
    }
});

app.get('/dashboard', (req, res) => {
    if(!req.session.user) {
        res.redirect('/login');
    } else {
        res.render('dashboard', { user: req.session.user });
    }
});

app.get('/logout', (req, res) => {
    if(req.session.user) {
        req.session.destroy();
    }

    res.redirect('/login');
});

// Delete the user's domain and DNS record
app.post('/delete', async (req, res) => {
    if(!req.session.user) {
        res.redirect('/login');
    } else {
        const { subdomain, wildcard } = req.session.user;
        const deleted = await deleteDNS(subdomain); // delete the DNS record
        if(!deleted) return res.send('It looks like an error occurred while deleting your domain. Please try again later.');

        if(wildcard) { // if user had a wildcard setup, delete it too
            const deleteWildcard = await deleteDNS('*.' + subdomain); // delete the wildcard DNS record
            if(!deleteWildcard) return res.send('It looks like an error occurred while deleting your wildcard. Please try again later.');
        }

        const users = await readUsers();
        const newUsers = users.filter(user => user.subdomain !== subdomain); // remove the user from the users.json file
        await saveUsers(newUsers);

        req.session.destroy();
        res.redirect('/signup/?deleted=true');
    }
});

// Check if a subdomain is available (soft check, NOT with the Cloudflare API)
app.post('/available', async (req, res) => {
    const { 'subdomain': upperSubdomain } = req.body;
    const subdomain = upperSubdomain.toLowerCase();
    const users = await readUsers();

    res.json({ success: !(users.some(user => user.subdomain === subdomain) || reserved.includes(subdomain)) }); // this is a soft check, we're going to use the Cloudflare API to check IF they decide to sign up
});

// Login and create a session
app.post('/login', rejectLoggedIn, LOGIN_RATE_LIMIT, async (req, res) => {
    const { 'subdomain': upperSubdomain, password, 'g-recaptcha-response': recaptchaToken } = req.body;
    let subdomain = upperSubdomain.toLowerCase();
    if(subdomain.endsWith(".redbox.my")) { subdomain = subdomain.slice(0, -".redbox.my".length) };
    const users = await readUsers();

    // Check if they have all the fields
    if (!subdomain || !password || !recaptchaToken) {
        return res.json({ error: 'It looks like your request was malformed. Please refresh the page and try again!' });
    }

    // Verify the reCAPTCHA
    if (!(await verifyRecaptcha(recaptchaToken))) {
        return res.json({ error: 'It looks like the reCAPTCHA verification failed. Please try again.' });
    }

    // Check if the user exists
    const user = users.find(user => user.subdomain === subdomain);
    if (!user) {
        return res.json({ error: 'It looks like this domain was not reserved! Please try again.' });
    }

    // Check if the password is correct
    const passwordMatch = await bcrypt.compare(password, user.hash);
    if (!passwordMatch) {
        return res.json({ error: 'It looks like your password was incorrect! Please try again.' });
    }

    req.session.user = user;
    res.json({ success: true, message: 'You have been successfully logged into the dashboard!' });
});

// Reserve a subdomain and update Cloudflare DNS
app.post('/signup', SIGNUP_RATE_LIMIT, rejectLoggedIn, async (req, res) => {
    const { 'subdomain': upperSubdomain, password, 'g-recaptcha-response': recaptchaToken } = req.body;
    const subdomain = upperSubdomain.toLowerCase();
    const users = await readUsers();

    // Check if they have all the fields
    if (!subdomain || !password || !recaptchaToken) {
        return res.json({ error: 'It looks like your request was malformed. Please refresh the page and try again!' });
    }

    // Check if subdomain and password is valid
    if(subdomain.length < 3 || subdomain.length > 60) {
        return res.json({ error: 'Subdomain must be between 3 and 60 characters.' });
    } else if(!/^[a-z0-9]+$/.test(subdomain)) {
        return res.json({ error: 'Subdomain can only contain letters and numbers.' });
    } else if(password.length < 6) {
        return res.json({ error: 'Password must be at least 6 characters long.' });
    } else if(password.length > 30) {
        return res.json({ error: 'Password must be less than 30 characters long.' });
    }

    // Verify the reCAPTCHA
    if (!(await verifyRecaptcha(recaptchaToken))) {
        return res.json({ error: 'It looks like the reCAPTCHA verification failed. Please try again.' });
    }

    // Check if subdomain is taken
    const isTaken = await isReserved(subdomain);
    if (users.find(user => user.subdomain === subdomain) || reserved.includes(subdomain) || isTaken) {
        return res.json({ error: 'It looks like this domain was already taken! Please try another.' });
    }

    const reserve = await reserveDNS(subdomain); // reserve the domain first before we create the user
    if(!reserve) return res.json({ error: 'A server error occurred, please try again later.' });

    const newUser = {
        subdomain,
        hash: await bcrypt.hash(password, 10), // hash the password w/ bcrypt
        ip: reserve.ip, // default IP address
        proxying: reserve.proxied, // default proxying status
		wildcard: false, // disabled by default
    };
    users.push(newUser);

    await saveUsers(users);
    req.session.user = newUser;
    res.json({ success: true, message: 'Your subdomain has been successfully reserved and is ready to be updated!' });
});

app.post("/update", UPDATE_RATE_LIMIT, async (req, res) => {
    if(!req.session.user) {
        res.redirect('/login');
    } else {
        const { ip, 'proxying': proxyingText, 'wildcard': wildcardText, password, 'g-recaptcha-response': recaptchaToken } = req.body;
        const proxying = proxyingText === "true";
		const wildcard = wildcardText === "true";

        // Verify the reCAPTCHA
        if (!(await verifyRecaptcha(recaptchaToken))) {
            return res.json({ error: 'It looks like the reCAPTCHA verification failed. Please try again.' });
        }

        const users = await readUsers();
        const user = users.find(user => user.subdomain === req.session.user.subdomain);

        if(password.length !== 0 && !(await bcrypt.compare(password, user.hash))) {
            if(password.length < 6) {
                return res.json({ error: 'Password must be at least 6 characters long.' });
            } else if(password.length > 30) {
                return res.json({ error: 'Password must be less than 30 characters long.' });
            } else {
                user.hash = await bcrypt.hash(password, 10); // update the password w/ bcrypt

                await saveUsers(users);
                req.session.user = user;
            }
        }

        if(ip !== user.ip || proxying !== user.proxying || wildcard !== user.wildcard) {
            if(!isIpOrDomain(ip)) {
                return res.json({ error: 'Please enter a valid IP address or CNAME domain.' });
            } else {
                const method = isIpOrDomain(ip) === 'ip' ? 'A' : 'CNAME';
                const update = await updateDNS(user.subdomain, ip, proxying, method); // update the DNS record
                if(!update) return res.json({ error: 'A server error occurred, please try again later.' });

                if(wildcard && !user.wildcard) { // if user has just setup their wildcard
                    const reserve = await reserveDNS('*.' + user.subdomain); // create the wildcard DNS record
                    if(!reserve) return res.json({ error: 'A server error occurred, please try again later.' });
                } else if(!wildcard && user.wildcard) { // if user wants to delete their wildcard
                    const deleted = await deleteDNS('*.' + user.subdomain); // delete the wildcard DNS record
                    if(!deleted) return res.send({ error: 'A server error occurred, please try again later.' });
                }

                if(wildcard) { // at the end, if they have a wildcard, update it
                    const update = await updateDNS('*.' + user.subdomain, ip, proxying, method); // update the DNS record
                    if(!update) return res.json({ error: 'A server error occurred, please try again later.' });
                }

                user.ip = ip;
                user.proxying = proxying;
				user.wildcard = wildcard;

                await saveUsers(users);
                req.session.user = user;
            }
        }

        res.json({ success: true });
    }
});

app.use((req, res, next) => {
    res.status(404).redirect('/');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
