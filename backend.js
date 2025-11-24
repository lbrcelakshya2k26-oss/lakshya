require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
require('dotenv').config();
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const { SESv2Client, SendEmailCommand } = require("@aws-sdk/client-sesv2");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, UpdateCommand, DeleteCommand, QueryCommand } = require("@aws-sdk/lib-dynamodb");


// const Razorpay = require('razorpay'); // Payment Disabled for now
const Razorpay = require('razorpay');
const crypto = require('crypto'); // Built-in Node module for security
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const app = express();

// --- 1. CONFIGURATION ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- SERVE ASSETS & SCRIPTS (SECURE) ---
app.use('/assets', express.static(path.join(__dirname, 'assets')));
// Point to public/js instead of just js
app.use('/js', express.static(path.join(__dirname, 'public/js')));
// Point to public/static instead of just static
app.use('/static', express.static(path.join(__dirname, 'public/static')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'lakshya_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// --- RAZORPAY SETUP ---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_Rj1XO8nMv3xR7J',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'XqfcDBCtT3RD570yw8fGT43u'
});

// --- 2. AWS SETUP (UPDATED WITH YOUR CREDENTIALS) ---



// DynamoDB Setup
const client = new DynamoDBClient({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: '+7xyGRP/P+5qZD955qgrC8GwvuOsA33wwzwe6abl'
    }
});
const docClient = DynamoDBDocumentClient.from(client);

const s3Client = new S3Client({
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: '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'
    }
});

// SES Setup
const sesClient = new SESv2Client({
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID || 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY || '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'
    }
});

// --- 3. HELPER FUNCTIONS ---

// Send Email via SES (Updated Logic)
async function sendEmail(to, subject, htmlContent) {
    // The 'to' field can be a string of comma-separated emails or an array.
    const toAddresses = Array.isArray(to)
        ? to
        : to.split(',').map(e => e.trim());

    const params = {
        FromEmailAddress: '"LAKSHYA 2K26" <support@testify-lac.com>', // Using the provided verified email
        Destination: {
            ToAddresses: toAddresses,
        },
        Content: {
            Simple: {
                Subject: {
                    Data: subject,
                    Charset: 'UTF-8',
                },
                Body: {
                    Html: {
                        Data: htmlContent,
                        Charset: 'UTF-8',
                    },
                },
            },
        },
    };

    try {
        const command = new SendEmailCommand(params);
        const data = await sesClient.send(command);
        console.log('Email sent successfully with SES:', data.MessageId);
        return true;
    } catch (error) {
        console.error('Error sending email with SES:', error);
        return false;
    }
}

// Middleware to check Authentication
const isAuthenticated = (role) => (req, res, next) => {
    if (req.session.user && req.session.user.role === role) {
        return next();
    }
    res.redirect('/login');
};

// --- 4. ROUTES: PUBLIC PAGES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/static/home.html')));
app.get('/home', (req, res) => res.sendFile(path.join(__dirname, 'public/static/home.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/static/login.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/static/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/static/register.html')));
app.get('/events', (req, res) => res.sendFile(path.join(__dirname, 'public/static/events.html')));
app.get('/culturals', (req, res) => res.sendFile(path.join(__dirname, 'public/static/culturals.html')));
app.get('/brochure', (req, res) => res.sendFile(path.join(__dirname, 'public/static/brochure.html')));
app.get('/committee', (req, res) => res.sendFile(path.join(__dirname, 'public/static/committee.html')));
app.get('/contact', (req, res) => res.sendFile(path.join(__dirname, 'public/static/contact.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public/static/about.html')));

app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public/static/terms&conditions.html')));



// --- 5. ROUTES: PARTICIPANT (PROTECTED) ---
app.get('/participant/dashboard', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/dashboard.html'));
});
app.get('/participant/events', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/events.html'));
});
app.get('/participant/cart', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/cart.html'));
});
app.get('/participant/my-registrations', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/my-registrations.html'));
});
app.get('/participant/certificates', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/certificates.html'));
});
app.get('/participant/feedback', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/feedback.html'));
});


// --- 6. ROUTES: COORDINATOR (PROTECTED) ---
app.get('/coordinator/dashboard', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/dashboard.html'));
});
app.get('/coordinator/attendance', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/attendance.html'));
});
app.get('/coordinator/payment-status', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/payments.html'));
});
app.get('/coordinator/assign-score', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/assign-score.html'));
});
app.get('/coordinator/registrations', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/registrations.html'));
});


// --- 7. ROUTES: ADMIN (PROTECTED) ---
app.get('/admin/dashboard', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/dashboard.html'));
});
app.get('/admin/add-event', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/add-event.html'));
});
app.get('/admin/manage-users', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/manage-users.html'));
});
app.get('/admin/committee', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/committee.html'));
});
app.get('/admin/departments', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/departments.html'));
});
app.get('/admin/setup-scoring', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/setup-scoring.html'));
});
app.get('/admin/view-scores', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/view-scores.html'));
});
app.get('/admin/manage-events', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/manage-events.html'));
});
app.get('/admin/manage-scoring', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/manage-scoring.html'));
});




// --- 8. API ROUTES: AUTHENTICATION ---
app.post('/api/auth/register', async (req, res) => {
    const { fullName, rollNo, email, mobile, college, password, stream, dept, year } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const params = {
        TableName: 'Lakshya_Users',
        Item: {
            email: email, role: 'participant', fullName, rollNo, mobile, college, stream, dept, year,
            password: hashedPassword, createdAt: new Date().toISOString()
        }
    };
    try { await docClient.send(new PutCommand(params)); res.status(200).json({ message: 'Registration successful' }); }
    catch (err) { res.status(500).json({ error: 'Registration failed', details: err }); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password, role } = req.body;
    const params = { TableName: 'Lakshya_Users', Key: { email } };
    try {
        const data = await docClient.send(new GetCommand(params));
        const user = data.Item;
        if (!user || user.role !== role) return res.status(401).json({ error: 'Invalid credentials' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid password' });

        // FIX: Saving DEPT and FULLNAME correctly to session
        req.session.user = { 
            email: user.email, 
            role: user.role, 
            name: user.fullName,
            dept: user.dept // Crucial for Coordinators
        };
        
        res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/send-otp', async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.otp = otp;
    
    try {
        await sendEmail(email, "LAKSHYA 2K26 OTP", `Your OTP is: ${otp}`);
        res.json({ message: 'OTP sent', debug_otp: otp });
    } catch (e) {
        res.status(500).json({ error: 'Failed to send OTP', details: e });
    }
});


// --- 9. API ROUTES: MOCKED PAYMENT & REGISTRATION ---
app.post('/api/register-event', isAuthenticated('participant'), async (req, res) => {
    const { eventId, deptName, paymentMode, teamName, teamMembers, submissionTitle, submissionAbstract, submissionUrl } = req.body;
    const user = req.session.user;

    // --- NEW CHECK: IS REGISTRATION OPEN FOR THIS DEPT? ---
    try {
        const statusId = `${eventId}#${deptName}`;
        const statusRes = await docClient.send(new GetCommand({
            TableName: 'Lakshya_EventStatus', // New Table
            Key: { statusId }
        }));
        
        // If a record exists and isOpen is false, block registration
        if (statusRes.Item && statusRes.Item.isOpen === false) {
            return res.status(403).json({ error: `Registrations for this event are currently closed by the ${deptName} department.` });
        }
    } catch (e) {
        console.warn("Status check skipped or failed", e);
    }
    // ------------------------------------------------------

    try {
        const checkParams = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'StudentIndex',
            KeyConditionExpression: 'studentEmail = :email',
            FilterExpression: 'eventId = :eid AND deptName = :dept',
            ExpressionAttributeValues: {
                ':email': user.email,
                ':eid': eventId,
                ':dept': deptName
            }
        };
        const existing = await docClient.send(new QueryCommand(checkParams));
        
        if (existing.Items && existing.Items.length > 0) {
            return res.status(400).json({ error: `You are already registered for this event in the ${deptName} department.` });
        }
    } catch (e) {
        console.error("Duplicate Check Error", e);
        return res.status(500).json({ error: 'Server validation failed' });
    }

    let eventTitle = eventId; 
    try {
        const eventRes = await docClient.send(new GetCommand({
            TableName: 'Lakshya_Events',
            Key: { eventId }
        }));
        if (eventRes.Item) eventTitle = eventRes.Item.title;
    } catch (e) {
        console.warn("Could not fetch event title for email");
    }

    const registrationId = uuidv4();
    const paymentStatus = 'PENDING'; 

    const params = {
        TableName: 'Lakshya_Registrations',
        Item: {
            registrationId,
            studentEmail: user.email,
            eventId,
            deptName,
            teamName: teamName || null, 
            teamMembers: teamMembers || [],
            submissionTitle: submissionTitle || null,
            submissionAbstract: submissionAbstract || null,
            submissionUrl: submissionUrl || null,
            paymentStatus: paymentStatus,
            paymentMode, 
            attendance: false,
            registeredAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));

        const subject = `Registration Confirmed: ${eventTitle}`;
        const teamInfo = teamName ? `<p><strong>Team Name:</strong> ${teamName}</p>` : '';
        let submissionInfo = '';
        if(submissionTitle) submissionInfo += `<p><strong>Submission:</strong> ${submissionTitle}</p>`;
        if(submissionUrl) submissionInfo += `<p><strong>File:</strong> <a href="${submissionUrl}">View Upload</a></p>`;

        const displayStatus = paymentStatus === 'COMPLETED' ? 'Paid' : 'Payment Pending';
        const statusColor = paymentStatus === 'COMPLETED' ? 'green' : 'orange';

        const emailBody = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
                <h2 style="color: #00d2ff; text-align: center;">LAKSHYA 2K26</h2>
                <p>Dear Participant,</p>
                <p>Thank you for registering for <strong>${eventTitle}</strong>. Below are your registration details:</p>
                <div style="background: #f9f9f9; padding: 15px; margin: 20px 0;">
                    <p><strong>Registration ID:</strong> ${registrationId}</p>
                    <p><strong>Event:</strong> ${eventTitle}</p>
                    <p><strong>Department:</strong> ${deptName}</p>
                    ${teamInfo}
                    ${submissionInfo}
                    <p><strong>Payment Status:</strong> <span style="color: ${statusColor}">${displayStatus}</span></p>
                </div>
                <p>Best Regards,<br>Team LAKSHYA</p>
            </div>
        `;

        await sendEmail(user.email, subject, emailBody);

        if (teamMembers && Array.isArray(teamMembers) && teamMembers.length > 0) {
            const memberEmails = teamMembers.filter(m => m.email).map(m => sendEmail(m.email, subject, emailBody));
            await Promise.all(memberEmails);
        }

        res.json({ message: 'Registration initiated', registrationId });
    } catch (err) {
        console.error("Reg Error", err);
        res.status(500).json({ error: 'Registration failed' });
    }
});
app.post('/api/payment/create-order', isAuthenticated('participant'), async (req, res) => {
    const { amount, couponCode } = req.body;
    let finalAmount = amount;
    let couponApplied = false;

    // Validate & Calculate Discount
    if (couponCode) {
        try {
            const couponRes = await docClient.send(new GetCommand({
                TableName: 'Lakshya_Coupons',
                Key: { code: couponCode.toUpperCase() }
            }));

            const coupon = couponRes.Item;

            if (coupon && coupon.usedCount < coupon.usageLimit) {
                const discount = (finalAmount * coupon.percentage) / 100;
                finalAmount = Math.round(finalAmount - discount);
                couponApplied = true;
            } else {
                console.warn(`Coupon ${couponCode} invalid or expired during order creation.`);
            }
        } catch (e) {
            console.error("Coupon Error in Order:", e);
        }
    }

    if (finalAmount < 1) finalAmount = 1;

    const options = {
        amount: finalAmount * 100,
        currency: "INR",
        receipt: "receipt_" + uuidv4().substring(0, 10),
    };

    try {
        const order = await razorpay.orders.create(options);

        // IMPORTANT: Increment usage count ONLY if we successfully created an order with it
        // Note: Strictly speaking, this should happen after successful payment verification to be 100% accurate,
        // but incrementing here reserves it. For simple use cases, this is acceptable.
        // To be atomic, you'd move this to the /verify endpoint, but then users might 'overuse' it simultaneously.
        // Let's increment here for reservation logic.
        if (couponApplied) {
            await docClient.send(new UpdateCommand({
                TableName: 'Lakshya_Coupons',
                Key: { code: couponCode.toUpperCase() },
                UpdateExpression: "set usedCount = usedCount + :inc",
                ExpressionAttributeValues: { ":inc": 1 }
            }));
        }

        res.json({
            id: order.id,
            amount: order.amount,
            currency: order.currency,
            key_id: process.env.RAZORPAY_KEY_ID
        });
    } catch (err) {
        res.status(500).json({ error: "Order creation failed" });
    }
});
app.get('/api/participant/dashboard-stats', isAuthenticated('participant'), async (req, res) => {
    const userEmail = req.session.user.email;

    try {
        // 1. Fetch User Details (To get Roll No)
        const userRes = await docClient.send(new GetCommand({
            TableName: 'Lakshya_Users',
            Key: { email: userEmail }
        }));
        const userDetails = userRes.Item || {};

        // 2. Fetch Registrations (For Stats)
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'StudentIndex',
            KeyConditionExpression: 'studentEmail = :email',
            ExpressionAttributeValues: { ':email': userEmail }
        };

        const data = await docClient.send(new QueryCommand(params));
        const registrations = data.Items || [];
        
        // Calculate payment status
        const total = registrations.length;
        const paid = registrations.filter(r => r.paymentStatus === 'COMPLETED').length;
        
        let status = 'None';
        if (total > 0) {
            if (paid === total) status = 'Paid';
            else if (paid > 0) status = 'Partial';
            else status = 'Pending';
        }

        res.json({
            name: userDetails.fullName || req.session.user.name,
            rollNo: userDetails.rollNo || '-', // Added Roll No here
            college: userDetails.college || '',
            mobile: userDetails.mobile || '',
            totalRegistrations: total,
            paymentStatus: status
        });

    } catch (err) {
        console.error("Dashboard Stats Error:", err);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

// --- REPLACE YOUR EXISTING VERIFY ROUTE WITH THIS ---
app.post('/api/payment/verify', isAuthenticated('participant'), async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, registrationIds, couponCode } = req.body;
    const userEmail = req.session.user.email;
    const userName = req.session.user.name || "Participant";

    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(body.toString())
        .digest('hex');

    if (expectedSignature === razorpay_signature) {
        try {
            if (registrationIds && Array.isArray(registrationIds)) {
                // 1. Update Database
                const updatePromises = registrationIds.map(regId => 
                    docClient.send(new UpdateCommand({
                        TableName: 'Lakshya_Registrations',
                        Key: { registrationId: regId },
                        UpdateExpression: "set paymentStatus = :s, paymentId = :p, paymentMode = :m, attendance = :a, couponUsed = :c, paymentDate = :d",
                        ExpressionAttributeValues: {
                            ":s": "COMPLETED",
                            ":p": razorpay_payment_id,
                            ":m": "ONLINE",
                            ":a": false,
                            ":c": couponCode || null,
                            ":d": new Date().toISOString()
                        }
                    }))
                );
                await Promise.all(updatePromises);

                // 2. Fetch Event Names for Email (Enhancement)
                // We fetch details for the first registration to get team info context, 
                // and loop through all to get event titles.
                // Note: Ideally, you'd query the Events table, but for simplicity, we'll assume generic names 
                // or you can fetch them if 'eventCache' is available server-side (it's usually client-side).
                // A robust way is to fetch the registration items back or rely on frontend passing titles (less secure).
                // BETTER: Let's fetch the just-updated registrations to get eventIds, then get titles.
                
                // For speed/simplicity in this snippet, we will send a generic success mail with IDs.
                // To show Event Titles, you would need to query your Lakshya_Events table using the eventIds from registrationIds.
                
                const dateStr = new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });

                // 3. Enhanced Email Template
                const subject = `Payment Successful - LAKSHYA 2K26`;
                const htmlContent = `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                        <div style="background-color: #00d2ff; padding: 20px; text-align: center;">
                            <h2 style="color: #ffffff; margin: 0; text-transform: uppercase;">Payment Confirmed</h2>
                        </div>
                        <div style="padding: 30px; background-color: #ffffff;">
                            <p style="font-size: 16px; color: #333;">Dear <strong>${userName}</strong>,</p>
                            <p style="color: #555; line-height: 1.6;">
                                We have successfully received your payment for <strong>LAKSHYA 2K26</strong>. 
                                Your registrations are now confirmed.
                            </p>
                            
                            <div style="background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-left: 4px solid #4caf50; border-radius: 4px;">
                                <p style="margin: 5px 0;"><strong>Transaction ID:</strong> ${razorpay_payment_id}</p>
                                <p style="margin: 5px 0;"><strong>Order ID:</strong> ${razorpay_order_id}</p>
                                <p style="margin: 5px 0;"><strong>Date:</strong> ${dateStr}</p>
                                <p style="margin: 5px 0;"><strong>Total Events:</strong> ${registrationIds.length}</p>
                                ${couponCode ? `<p style="margin: 5px 0; color: #00d2ff;"><strong>Coupon Applied:</strong> ${couponCode}</p>` : ''}
                            </div>

                            <p style="color: #777; font-size: 14px;">
                                Please visit your dashboard to view full registration details, team members, and download your event passes/receipts.
                            </p>

                            <div style="text-align: center; margin-top: 30px;">
                                <a href="https://testify-lac.com/participant/my-registrations" style="background-color: #3a7bd5; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">Go to Dashboard</a>
                            </div>
                        </div>
                        <div style="background-color: #f1f1f1; padding: 15px; text-align: center; color: #888; font-size: 12px;">
                            &copy; 2026 LAKSHYA Fest Committee. All rights reserved.<br>
                            Need help? Contact <a href="mailto:support@testify-lac.com">support@testify-lac.com</a>
                        </div>
                    </div>
                `;

                // Send Email (Non-blocking)
                sendEmail(userEmail, subject, htmlContent).catch(console.error);
            }
            res.json({ status: 'success' });
        } catch (err) {
            console.error("DB Error:", err);
            res.status(500).json({ error: 'Payment valid but DB update failed' });
        }
    } else {
        res.status(400).json({ error: 'Invalid signature' });
    }
});

// --- 10. COORDINATOR ROUTES ---
app.post('/api/coordinator/mark-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId, status } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": status }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Attendance updated' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.post('/api/coordinator/mark-paid', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentMode = :m",
        ExpressionAttributeValues: {
            ":s": "COMPLETED",
            ":m": "CASH"
        }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Payment marked as received' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

// Add this inside your backend.js under Admin Routes

app.get('/api/admin/stats', isAuthenticated('admin'), async (req, res) => {
    try {
        const [users, events, regs] = await Promise.all([
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Users', Select: 'COUNT' })),
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Events', Select: 'COUNT' })),
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Registrations' }))
        ]);

        const registrations = regs.Items || [];
        
        // 1. Calculate Revenue
        const totalRevenue = registrations.reduce((sum, r) => {
            return r.paymentStatus === 'COMPLETED' ? sum + 200 : sum; 
        }, 0);

        // 2. Analytics: Registrations by Department
        const deptCounts = {};
        registrations.forEach(r => {
            const d = r.deptName || 'General';
            deptCounts[d] = (deptCounts[d] || 0) + 1;
        });

        // 3. Analytics: Payment Status
        const paymentCounts = { Paid: 0, Pending: 0 };
        registrations.forEach(r => {
            if(r.paymentStatus === 'COMPLETED') paymentCounts.Paid++;
            else paymentCounts.Pending++;
        });

        res.json({
            totalUsers: users.Count,
            totalEvents: events.Count,
            totalRegistrations: regs.Count,
            totalRevenue: totalRevenue,
            deptCounts: deptCounts,      // For Bar Chart
            paymentCounts: paymentCounts // For Pie Chart
        });

    } catch (err) {
        console.error("Admin Stats Error:", err);
        res.status(500).json({ error: 'Failed to load admin stats' });
    }
});
app.get('/api/admin/student-details', isAuthenticated('admin'), async (req, res) => {
    const { email } = req.query;
    try {
        const data = await docClient.send(new GetCommand({ TableName: 'Lakshya_Users', Key: { email } }));
        if (data.Item) {
            const { password, ...studentData } = data.Item;
            res.json(studentData);
        } else { res.status(404).json({ error: 'Student not found' }); }
    } catch (err) { res.status(500).json({ error: 'Failed to fetch details' }); }
});
app.get('/admin/registrations', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/registrations.html'));
});
app.get('/api/admin/all-registrations', isAuthenticated('admin'), async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Registrations' }));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Admin Reg Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch registrations' });
    }
});


app.post('/api/admin/create-user', isAuthenticated('admin'), async (req, res) => {
    const { email, password, role, fullName, dept } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const params = {
        TableName: 'Lakshya_Users',
        Item: {
            email,
            role, // 'coordinator'
            fullName,
            dept, // Store dept for coordinators
            password: hashedPassword,
            createdAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'User created successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Creation failed' });
    }
});
// Add Committee Member
// app.post('/api/admin/add-committee-member', isAuthenticated('admin'), async (req, res) => {
//     const { name, role, category, imgUrl } = req.body;
//     const memberId = uuidv4();

//     const params = {
//         TableName: 'Lakshya_Committee', // You need to create this table or store in a general config table
//         Item: {
//             memberId,
//             name,
//             role,
//             category,
//             imgUrl
//         }
//     };

//     try {
//         await docClient.send(new PutCommand(params));
//         res.json({ message: 'Member added' });
//     } catch (err) {
//         res.status(500).json({ error: 'Failed to add member' });
//     }
// });

// Add this inside the "Admin Routes" section of backend.js

// --- 1. Fetch Departments ---
app.get('/api/admin/departments', async (req, res) => {
    const params = { TableName: 'Lakshya_Departments' }; // Create this table in DynamoDB
    try {
        const data = await docClient.send(new ScanCommand(params));
        res.json(data.Items);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch departments' });
    }
});

app.post('/api/admin/add-event', isAuthenticated('admin'), upload.single('image'), async (req, res) => {
    try {
        const { title, type, description, teamSize, fee, departments, sections } = req.body;
        // Note: departments and sections will come as JSON strings if sent via FormData, need parsing.

        let imageUrl = 'default.jpg';

        if (req.file) {
            const fileContent = req.file.buffer;
            const fileName = `events/${uuidv4()}-${req.file.originalname}`;
            const uploadParams = {
                Bucket: 'hirewithusjobapplications',
                Key: fileName,
                Body: fileContent,
                ContentType: req.file.mimetype,
                // ACL: 'public-read' // S3 buckets often block ACLs now, assume bucket policy allows public read or use CloudFront.
                // For this specific bucket name, I'll assume standard config.
            };
            await s3Client.send(new PutObjectCommand(uploadParams));
            imageUrl = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;
        }

        const eventId = uuidv4();
        const params = {
            TableName: 'Lakshya_Events',
            Item: {
                eventId,
                title,
                type,
                description,
                teamSize,
                fee,
                departments: JSON.parse(departments), // Parse back to array
                sections: JSON.parse(sections),       // Parse back to array
                imageUrl,
                createdAt: new Date().toISOString()
            }
        };
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Event created' });
    } catch (err) {
        console.error("Event Add Error:", err);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

// --- 2. Add Department ---
app.post('/api/admin/add-department', isAuthenticated('admin'), async (req, res) => {
    const { name } = req.body;
    const deptId = uuidv4();
    
    const params = {
        TableName: 'Lakshya_Departments',
        Item: {
            deptId,
            name: name.toUpperCase(),
            createdAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Department added' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add department' });
    }
});
app.post('/api/admin/delete-department', isAuthenticated('admin'), async (req, res) => {
    const { deptId } = req.body;
    
    const params = {
        TableName: 'Lakshya_Departments',
        Key: { deptId }
    };

    try {
        await docClient.send(new DeleteCommand(params));
        res.json({ message: 'Department deleted' });
    } catch (err) {
        console.error("Dept Delete Error:", err);
        res.status(500).json({ error: 'Failed to delete department' });
    }
});
app.get('/api/events', async (req, res) => {
    const params = { TableName: 'Lakshya_Events' };
    try {
        const data = await docClient.send(new ScanCommand(params));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Event Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// Get My Registrations
app.get('/api/participant/my-registrations-data', isAuthenticated('participant'), async (req, res) => {
    const userEmail = req.session.user.email;
    
    const params = {
        TableName: 'Lakshya_Registrations',
        IndexName: 'StudentIndex',
        KeyConditionExpression: 'studentEmail = :email',
        ExpressionAttributeValues: { ':email': userEmail }
    };

    try {
        const data = await docClient.send(new QueryCommand(params));
        res.json(data.Items);
    } catch (err) {
        console.error("Reg Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch registrations' });
    }
    });
// --- COORDINATOR API ROUTES ---

// 1. Get Dashboard Data (Filtered by Coordinator's Dept)
app.get('/api/coordinator/dashboard-data', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const userDept = req.session.user.dept;
        
        if (!userDept) {
            return res.json({ dept: 'Unknown', registrations: [] });
        }
        
        // 1. Fetch all registrations for department
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            ExpressionAttributeValues: { ':dept': userDept }
        };

        const data = await docClient.send(new QueryCommand(params));
        let registrations = data.Items || [];

  

        res.json({ dept: userDept, registrations: registrations });
    } catch (err) {
        console.error("Coord Dashboard Error:", err);
        res.status(500).json({ error: 'Failed to load data' });
    }
});

// 2. Quick Attendance (By Reg ID or Email - Simplified lookup)
app.post('/api/coordinator/quick-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { identifier } = req.body; // Can be Reg ID
    
    // Ideally, we scan or query. For simplicity, let's assume it's the Registration ID (Partition Key)
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId: identifier },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": true },
        ReturnValues: "ALL_NEW"
    };

    try {
        const data = await docClient.send(new UpdateCommand(params));
        if (data.Attributes) {
            res.json({ 
                message: 'Success', 
                studentEmail: data.Attributes.studentEmail,
                eventId: data.Attributes.eventId
            });
        } else {
            res.status(404).json({ error: 'Registration ID not found' });
        }
    } catch (err) {
        console.error("Quick Attend Error:", err);
        res.status(500).json({ error: 'Lookup failed' });
    }
});

app.get('/api/coordinator/dashboard-data', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const userDept = req.session.user.dept;
        
        if (!userDept) {
            return res.json({ dept: 'Unknown', registrations: [] });
        }
        
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            ExpressionAttributeValues: { ':dept': userDept }
        };

        const data = await docClient.send(new QueryCommand(params));
        res.json({ dept: userDept, registrations: data.Items || [] });
    } catch (err) {
        console.error("Coord Dashboard Error:", err);
        res.status(500).json({ error: 'Failed to load data' });
    }
});

app.post('/api/coordinator/quick-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { identifier } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId: identifier },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": true },
        ReturnValues: "ALL_NEW"
    };
    try {
        const data = await docClient.send(new UpdateCommand(params));
        if (data.Attributes) {
            res.json({ message: 'Success', studentEmail: data.Attributes.studentEmail, eventId: data.Attributes.eventId });
        } else {
            res.status(404).json({ error: 'Registration ID not found' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Lookup failed' });
    }
});

app.post('/api/coordinator/mark-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId, status } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": status }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Attendance updated' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.post('/api/coordinator/mark-paid', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentMode = :m",
        ExpressionAttributeValues: { ":s": "COMPLETED", ":m": "CASH" }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Payment marked as received' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.get('/api/coordinator/my-events', isAuthenticated('coordinator'), async (req, res) => {
    const userDept = req.session.user.dept;
    if (!userDept) return res.json([]);

    // In a real app with proper GSIs, we would Query. 
    // Here we scan events and filter in memory (simple for small scale)
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        const allEvents = data.Items || [];
        
        // Filter events where this department is eligible
        const myEvents = allEvents.filter(e => e.departments && e.departments.includes(userDept));
        res.json(myEvents);
    } catch(e) {
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// ADDED: Fetch students for a specific event
app.get('/api/coordinator/event-students', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId } = req.query;
    const userDept = req.session.user.dept;

    const params = {
        TableName: 'Lakshya_Registrations',
        IndexName: 'DepartmentIndex',
        KeyConditionExpression: 'deptName = :dept',
        FilterExpression: 'eventId = :eid AND paymentStatus = :paid', // Only PAID students
        ExpressionAttributeValues: {
            ':dept': userDept,
            ':eid': eventId,
            ':paid': 'COMPLETED'
        }
    };

    try {
        const data = await docClient.send(new QueryCommand(params));
        res.json(data.Items || []);
    } catch(e) {
        console.error(e);
        res.status(500).json({ error: 'Failed to fetch students' });
    }
});
app.post('/api/coordinator/mark-paid', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentMode = :m",
        ExpressionAttributeValues: { 
            ":s": "COMPLETED", 
            ":m": "CASH" 
        }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Payment marked as received' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.get('/api/coordinator/pending-payments', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const userDept = req.session.user.dept;
        
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            // Filter: Get everything that is NOT 'COMPLETED'
            FilterExpression: 'paymentStatus <> :paid',
            ExpressionAttributeValues: {
                ':dept': userDept,
                ':paid': 'COMPLETED'
            }
        };

        const data = await docClient.send(new QueryCommand(params));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Pending Payments Error:", err);
        res.status(500).json({ error: 'Failed to fetch data' });
    }
});

app.get('/api/coordinator/student-details', isAuthenticated('coordinator'), async (req, res) => {
    const { email } = req.query;
    try {
        const params = {
            TableName: 'Lakshya_Users',
            Key: { email }
        };
        const data = await docClient.send(new GetCommand(params));
        if (data.Item) {
            // Don't send password
            const { password, ...studentData } = data.Item;
            res.json(studentData);
        } else {
            res.status(404).json({ error: 'Student not found' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch student details' });
    }
});
app.post('/api/coordinator/export-data', isAuthenticated('coordinator'), async (req, res) => {
    const { emails } = req.body; 
    
    if (!emails || !Array.isArray(emails) || emails.length === 0) {
        return res.json({});
    }

    // Deduplicate emails to save processing
    const uniqueEmails = [...new Set(emails)];

    try {
        // We use Parallel GetItem.
        // FIX: 'year' is a reserved keyword in DynamoDB. 
        // We must use ExpressionAttributeNames to fetch it safely.
        const userPromises = uniqueEmails.map(email => 
            docClient.send(new GetCommand({
                TableName: 'Lakshya_Users',
                Key: { email },
                // We map #y to 'year' in ExpressionAttributeNames below
                ProjectionExpression: 'email, fullName, rollNo, dept, mobile, #y, college',
                ExpressionAttributeNames: { "#y": "year" } 
            }))
        );

        const results = await Promise.all(userPromises);
        
        // Map the results: { "student@email.com": { fullName: "...", rollNo: "..." } }
        const userMap = {};
        results.forEach(r => {
            if (r.Item) {
                userMap[r.Item.email] = r.Item;
            }
        });

        res.json(userMap);

    } catch (err) {
        console.error("Export Data Error:", err);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});
app.post('/api/admin/save-scheme', isAuthenticated('admin'), async (req, res) => {
    const { eventId, deptName, criteria } = req.body;
    const schemeId = `${eventId}#${deptName}`; // Composite ID

    const params = {
        TableName: 'Lakshya_ScoringSchemes',
        Item: {
            schemeId,
            eventId,
            deptName,
            criteria: JSON.parse(criteria),
            isLocked: false, // Default to open
            updatedAt: new Date().toISOString()
        },
        // CRITICAL: Prevents overwriting an existing scheme
        ConditionExpression: 'attribute_not_exists(schemeId)'
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Scoring scheme saved successfully' });
    } catch (err) {
        if (err.name === 'ConditionalCheckFailedException') {
            res.status(400).json({ error: 'A scoring scheme already exists for this Event & Department. Please use "Manage Scoring" to edit it.' });
        } else {
            console.error("Save Scheme Error:", err);
            res.status(500).json({ error: 'Failed to save scheme' });
        }
    }
});

app.get('/api/admin/all-schemes', isAuthenticated('admin'), async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_ScoringSchemes' }));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Fetch Schemes Error:", err);
        res.status(500).json({ error: 'Failed to load schemes' });
    }
});

// --- ADMIN: UPDATE SCHEME (Edit / Unlock) ---
app.post('/api/admin/update-scheme', isAuthenticated('admin'), async (req, res) => {
    const { schemeId, criteria, isLocked } = req.body;

    const params = {
        TableName: 'Lakshya_ScoringSchemes',
        Key: { schemeId },
        UpdateExpression: "set criteria = :c, isLocked = :l, updatedAt = :u",
        ExpressionAttributeValues: {
            ":c": JSON.parse(criteria),
            ":l": isLocked,
            ":u": new Date().toISOString()
        }
    };

    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Scheme updated successfully' });
    } catch (err) {
        console.error("Update Scheme Error:", err);
        res.status(500).json({ error: 'Failed to update scheme' });
    }
});

// --- ADMIN: DELETE SCHEME ---
app.post('/api/admin/delete-scheme', isAuthenticated('admin'), async (req, res) => {
    const { schemeId } = req.body;
    try {
        await docClient.send(new DeleteCommand({
            TableName: 'Lakshya_ScoringSchemes',
            Key: { schemeId }
        }));
        res.json({ message: 'Scheme deleted successfully' });
    } catch (err) {
        console.error("Delete Scheme Error:", err);
        res.status(500).json({ error: 'Failed to delete scheme' });
    }
});
// 2. COORDINATOR: Get Data for Grading (Scheme + Present Students)
app.get('/api/coordinator/scoring-details', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId } = req.query;
    const deptName = req.session.user.dept;

    if (!eventId || !deptName) return res.status(400).json({ error: "Missing params" });

    try {
        // A. Fetch Scheme
        const schemeId = `${eventId}#${deptName}`;
        const schemeRes = await docClient.send(new GetCommand({
            TableName: 'Lakshya_ScoringSchemes',
            Key: { schemeId }
        }));

        const scheme = schemeRes.Item;
        if (!scheme) {
            return res.json({ enabled: false, message: "Admin has not configured scoring for this event/dept yet." });
        }

        // B. Fetch Students (Only PRESENT ones)
        const regParams = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            FilterExpression: 'eventId = :eid AND attendance = :att', 
            ExpressionAttributeValues: {
                ':dept': deptName,
                ':eid': eventId,
                ':att': true // Only Present
                // Note: In DynamoDB boolean storage, ensure this matches how you saved it (true vs "true")
            }
        };

        const regData = await docClient.send(new QueryCommand(regParams));
        const students = regData.Items || [];

        // Check if results are already finalized for this batch
        // We can store a 'locked' flag on the Scheme or check individual students.
        // Let's check the scheme first.
        const isLocked = scheme.isLocked === true;

        res.json({
            enabled: true,
            scheme: scheme.criteria,
            isLocked: isLocked,
            students: students.map(s => ({
                registrationId: s.registrationId,
                studentEmail: s.studentEmail,
                totalScore: s.totalScore || 0,
                scoreBreakdown: s.scoreBreakdown || {}, // { "Logic": 8, "Syntax": 5 }
            }))
        });

    } catch (err) {
        console.error("Scoring Details Error:", err);
        res.status(500).json({ error: "Failed to load scoring data" });
    }
});

// 3. COORDINATOR: Submit/Finalize Scores
app.post('/api/coordinator/submit-scores', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId, scores, finalize } = req.body; 
    // scores = [ { registrationId: "...", breakdown: {...}, total: 50 }, ... ]
    const deptName = req.session.user.dept;

    try {
        // 1. Update each student's record
        // DynamoDB BatchWriteItem doesn't support updates, so we use Promise.all with UpdateCommand
        const updatePromises = scores.map(student => {
            return docClient.send(new UpdateCommand({
                TableName: 'Lakshya_Registrations',
                Key: { registrationId: student.registrationId },
                UpdateExpression: "set scoreBreakdown = :sb, totalScore = :ts",
                ExpressionAttributeValues: {
                    ":sb": student.breakdown,
                    ":ts": student.total
                }
            }));
        });

        await Promise.all(updatePromises);

        // 2. If Final Submit, Lock the Scheme
        if (finalize) {
            const schemeId = `${eventId}#${deptName}`;
            await docClient.send(new UpdateCommand({
                TableName: 'Lakshya_ScoringSchemes',
                Key: { schemeId },
                UpdateExpression: "set isLocked = :l",
                ExpressionAttributeValues: { ":l": true }
            }));
        }

        res.json({ message: finalize ? "Scores Finalized & Locked" : "Scores Saved Successfully" });

    } catch (err) {
        console.error("Submit Scores Error:", err);
        res.status(500).json({ error: "Failed to save scores" });
    }
});

// --- EXISTING APIs (Keep these for context) ---

app.get('/api/events', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/departments', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Departments' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/coordinator/my-events', isAuthenticated('coordinator'), async (req, res) => {
    const userDept = req.session.user.dept;
    if (!userDept) return res.json([]);
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        const allEvents = data.Items || [];
        const myEvents = allEvents.filter(e => e.departments && e.departments.includes(userDept));
        res.json(myEvents);
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password, role } = req.body;
    const params = { TableName: 'Lakshya_Users', Key: { email } };
    try {
        const data = await docClient.send(new GetCommand(params));
        const user = data.Item;
        if (!user || user.role !== role) return res.status(401).json({ error: 'Invalid credentials' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid password' });

        req.session.user = { 
            email: user.email, 
            role: user.role, 
            name: user.fullName,
            dept: user.dept 
        };
        
        res.status(200).json({ message: 'Login successful' });
    } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});
// --- 11. API ROUTES: PERSISTENT CART ---

// Get User Cart
app.get('/api/cart', isAuthenticated('participant'), async (req, res) => {
    const email = req.session.user.email;
    const params = {
        TableName: 'Lakshya_Cart', // You must create this table in DynamoDB (PK: email)
        Key: { email }
    };

    try {
        const data = await docClient.send(new GetCommand(params));
        // Return empty array if no cart exists yet
        res.json(data.Item ? data.Item.items : []); 
    } catch (err) {
        console.error("Get Cart Error:", err);
        res.status(500).json({ error: 'Failed to fetch cart' });
    }
});

// Update User Cart (Overwrites existing list)
app.post('/api/cart', isAuthenticated('participant'), async (req, res) => {
    const email = req.session.user.email;
    const { items } = req.body; // Expecting Array of cart items

    const params = {
        TableName: 'Lakshya_Cart',
        Item: {
            email,
            items,
            updatedAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Cart saved' });
    } catch (err) {
        console.error("Save Cart Error:", err);
        res.status(500).json({ error: 'Failed to save cart' });
    }
});

// Clear Cart
app.delete('/api/cart', isAuthenticated('participant'), async (req, res) => {
    const email = req.session.user.email;
    try {
        await docClient.send(new DeleteCommand({
            TableName: 'Lakshya_Cart',
            Key: { email }
        }));
        res.json({ message: 'Cart cleared' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to clear cart' });
    }
});

app.post('/api/admin/export-data', isAuthenticated('admin'), async (req, res) => {
    const { emails } = req.body;
    
    if (!emails || !Array.isArray(emails) || emails.length === 0) {
        return res.json({});
    }

    // Deduplicate emails
    const uniqueEmails = [...new Set(emails)];

    try {
        // Use Parallel GetItem for efficiency (instead of Scan)
        // Fetching: email, fullName, mobile, college, rollNo, dept, year
        const userPromises = uniqueEmails.map(email => 
            docClient.send(new GetCommand({
                TableName: 'Lakshya_Users',
                Key: { email },
                ProjectionExpression: 'email, fullName, mobile, college, rollNo, dept, #y',
                ExpressionAttributeNames: { "#y": "year" } // Handle reserved keyword
            }))
        );

        const results = await Promise.all(userPromises);
        
        const userMap = {};
        results.forEach(r => {
            if (r.Item) {
                userMap[r.Item.email] = r.Item;
            }
        });

        res.json(userMap);

    } catch (err) {
        console.error("Admin Export Error:", err);
        res.status(500).json({ error: 'Failed to export data' });
    }
});

app.get('/api/admin/scores', isAuthenticated('admin'), async (req, res) => {
    const { eventId, deptName } = req.query;

    try {
        // Start with a basic scan
        const scanParams = {
            TableName: 'Lakshya_Registrations',
            // Only fetch records that have a score
            FilterExpression: 'attribute_exists(totalScore)' 
        };

        // Apply Filters if specific ones are selected
        const filters = [];
        const attrValues = {};
        const attrNames = {};

        if (eventId && eventId !== 'all') {
            filters.push('eventId = :eid');
            attrValues[':eid'] = eventId;
        }
        if (deptName && deptName !== 'all') {
            filters.push('#d = :dn');
            attrValues[':dn'] = deptName;
            attrNames['#d'] = 'deptName'; // Handle reserved word safety if needed
        }

        if (filters.length > 0) {
            scanParams.FilterExpression += ' AND ' + filters.join(' AND ');
            scanParams.ExpressionAttributeValues = attrValues;
            if (Object.keys(attrNames).length > 0) scanParams.ExpressionAttributeNames = attrNames;
        }

        const data = await docClient.send(new ScanCommand(scanParams));
        let items = data.Items || [];

        // Sort by Score (Descending) to show Rank
        items.sort((a, b) => parseFloat(b.totalScore) - parseFloat(a.totalScore));

        res.json(items);
    } catch (err) {
        console.error("Admin Score Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch scores' });
    }
});

// --- ADMIN: DELETE EVENT ---
app.post('/api/admin/delete-event', isAuthenticated('admin'), async (req, res) => {
    const { eventId } = req.body;
    try {
        await docClient.send(new DeleteCommand({
            TableName: 'Lakshya_Events',
            Key: { eventId }
        }));
        res.json({ message: 'Event deleted successfully' });
    } catch (err) {
        console.error("Delete Event Error:", err);
        res.status(500).json({ error: 'Failed to delete event' });
    }
});

// --- ADMIN: UPDATE EVENT ---
app.post('/api/admin/update-event', isAuthenticated('admin'), upload.single('image'), async (req, res) => {
    try {
        const { eventId, title, type, description, fee, departments, sections } = req.body;
        
        // 1. Prepare Update Expression
        // We build this dynamically based on whether an image was uploaded
        let updateExp = "set title=:t, #type=:ty, description=:d, fee=:f, departments=:depts, sections=:sec";
        let expValues = {
            ':t': title,
            ':ty': type,
            ':d': description,
            ':f': fee,
            ':depts': JSON.parse(departments), // Parse back from FormData string
            ':sec': JSON.parse(sections)
        };
        
        // 2. Handle Image Upload (Only if new image provided)
        if (req.file) {
            const fileContent = req.file.buffer;
            const fileName = `events/${uuidv4()}-${req.file.originalname}`;
            const uploadParams = {
                Bucket: 'hirewithusjobapplications',
                Key: fileName,
                Body: fileContent,
                ContentType: req.file.mimetype
            };
            await s3Client.send(new PutObjectCommand(uploadParams));
            const imageUrl = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;
            
            updateExp += ", imageUrl=:img";
            expValues[':img'] = imageUrl;
        }

        // 3. Update DynamoDB
        const params = {
            TableName: 'Lakshya_Events',
            Key: { eventId },
            UpdateExpression: updateExp,
            ExpressionAttributeValues: expValues,
            ExpressionAttributeNames: { "#type": "type" } // 'type' is reserved keyword
        };

        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Event updated successfully' });

    } catch (err) {
        console.error("Update Event Error:", err);
        res.status(500).json({ error: 'Failed to update event' });
    }
});

app.post('/api/admin/add-committee-member', isAuthenticated('admin'), upload.single('image'), async (req, res) => {
    try {
        const { name, role, category } = req.body;
        let imageUrl = 'assets/default-user.png'; // Fallback

        if (req.file) {
            const fileContent = req.file.buffer;
            const fileName = `committee/${uuidv4()}-${req.file.originalname}`;
            const uploadParams = {
                Bucket: 'hirewithusjobapplications', // Your Bucket
                Key: fileName,
                Body: fileContent,
                ContentType: req.file.mimetype
            };
            await s3Client.send(new PutObjectCommand(uploadParams));
            imageUrl = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;
        }

        const memberId = uuidv4();
        const params = {
            TableName: 'Lakshya_Committee',
            Item: {
                memberId,
                name,
                role,
                category, // e.g., "Chief Patrons", "CSE", "ECE"
                imageUrl,
                createdAt: new Date().toISOString()
            }
        };

        await docClient.send(new PutCommand(params));
        res.json({ message: 'Member added successfully' });

    } catch (err) {
        console.error("Add Member Error:", err);
        res.status(500).json({ error: 'Failed to add member' });
    }
});

// 2. Get All Committee Members (Public)
app.get('/api/committee', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Committee' }));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Fetch Committee Error:", err);
        res.status(500).json({ error: 'Failed to fetch committee' });
    }
});

// 3. Delete Committee Member (Admin)
app.post('/api/admin/delete-committee-member', isAuthenticated('admin'), async (req, res) => {
    const { memberId } = req.body;
    try {
        await docClient.send(new DeleteCommand({
            TableName: 'Lakshya_Committee',
            Key: { memberId }
        }));
        res.json({ message: 'Member deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete' });
    }
});

app.post('/api/auth/forgot-password-request', async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 15 * 60 * 1000; // 15 mins expiry

    try {
        // Check if user exists first
        const userCheck = await docClient.send(new GetCommand({
            TableName: 'Lakshya_Users',
            Key: { email }
        }));

        if (!userCheck.Item) {
            return res.status(404).json({ error: 'Email not registered' });
        }

        // Save OTP to user record
        const params = {
            TableName: 'Lakshya_Users',
            Key: { email },
            UpdateExpression: "set resetOtp = :o, resetOtpExp = :e",
            ExpressionAttributeValues: {
                ":o": otp,
                ":e": expiry
            }
        };

        await docClient.send(new UpdateCommand(params));
        
        // Send Email
        await sendEmail(email, "LAKSHYA 2K26 - Password Reset OTP", 
            `<p>Your OTP to reset your password is: <strong>${otp}</strong></p><p>This OTP expires in 15 minutes.</p>`);

        res.json({ message: 'OTP sent to your email' });

    } catch (err) {
        console.error("Forgot Pass Error:", err);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// 2. Reset Password (Verify OTP & Update)
app.post('/api/auth/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
        const data = await docClient.send(new GetCommand({
            TableName: 'Lakshya_Users',
            Key: { email }
        }));
        
        const user = data.Item;
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Validate OTP
        if (!user.resetOtp || user.resetOtp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }
        if (Date.now() > user.resetOtpExp) {
            return res.status(400).json({ error: 'OTP expired' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password and clear OTP
        const updateParams = {
            TableName: 'Lakshya_Users',
            Key: { email },
            UpdateExpression: "set password = :p remove resetOtp, resetOtpExp",
            ExpressionAttributeValues: {
                ":p": hashedPassword
            }
        };

        await docClient.send(new UpdateCommand(updateParams));
        res.json({ message: 'Password reset successfully. You can now login.' });

    } catch (err) {
        console.error("Reset Pass Error:", err);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

app.get('/admin/coupons', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/coupons.html'));
});

// 2. Create Coupon API
app.post('/api/admin/create-coupon', isAuthenticated('admin'), async (req, res) => {
    const { code, percentage, limit } = req.body; // Added 'limit'
    
    if (!code || !percentage || !limit) return res.status(400).json({ error: 'Code, Percentage, and Usage Limit are required' });

    const params = {
        TableName: 'Lakshya_Coupons',
        Item: {
            code: code.toUpperCase(),
            percentage: parseInt(percentage),
            usageLimit: parseInt(limit), // Max allowed uses
            usedCount: 0,                // Initial usage
            createdAt: new Date().toISOString()
        },
        ConditionExpression: 'attribute_not_exists(code)'
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Coupon created successfully' });
    } catch (err) {
        if(err.name === 'ConditionalCheckFailedException') {
            res.status(400).json({ error: 'Coupon code already exists' });
        } else {
            console.error("Create Coupon Error:", err);
            res.status(500).json({ error: 'Failed to create coupon' });
        }
    }
});

// 3. Get All Coupons API
app.get('/api/admin/coupons', isAuthenticated('admin'), async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Coupons' }));
        res.json(data.Items || []);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch coupons' });
    }
});

// 4. Delete Coupon API
app.post('/api/admin/delete-coupon', isAuthenticated('admin'), async (req, res) => {
    try {
        await docClient.send(new DeleteCommand({ TableName: 'Lakshya_Coupons', Key: { code: req.body.code } }));
        res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ error: 'Delete failed' }); }
});


app.post('/api/coupon/validate', isAuthenticated('participant'), async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code required" });

    try {
        const data = await docClient.send(new GetCommand({
            TableName: 'Lakshya_Coupons',
            Key: { code: code.toUpperCase() }
        }));

        if (!data.Item) return res.status(404).json({ error: "Invalid Coupon" });

        const coupon = data.Item;

        // Check Validity
        if (coupon.usedCount >= coupon.usageLimit) {
            return res.status(400).json({ error: "This coupon has expired (Usage limit reached)" });
        }

        res.json({ 
            code: coupon.code, 
            percentage: coupon.percentage,
            message: `${coupon.percentage}% Discount Applied!`
        });
    } catch (err) {
        res.status(500).json({ error: "Validation failed" });
    }
});

//---------------------------------------NEW PROCESS   ----------------------------//   

// --- NEW HELPER: UPLOAD FILE & RETURN URL (For Cart/Academic Flow) ---
app.post('/api/utility/upload-file', isAuthenticated('participant'), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        const user = req.session.user;
        const fileExt = req.file.originalname.split('.').pop();
        // Create a unique path in S3
        const fileName = `temp_uploads/${user.email}_${uuidv4()}.${fileExt}`;

        const uploadParams = {
            Bucket: 'hirewithusjobapplications', // Your Bucket Name
            Key: fileName,
            Body: req.file.buffer,
            ContentType: req.file.mimetype
            // ACL: 'public-read' // Uncomment if your bucket allows ACLs
        };

        await s3Client.send(new PutObjectCommand(uploadParams));
        
        // Construct and return the URL
        const fileUrl = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;

        res.json({ url: fileUrl });
    } catch (e) {
        console.error("Upload Helper Error:", e);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.get('/api/coordinator/submissions', isAuthenticated('coordinator'), async (req, res) => {
    const userDept = req.session.user.dept;
    if (!userDept) return res.status(400).json({ error: "No department assigned" });

    try {
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            ExpressionAttributeValues: { ':dept': userDept }
        };

        const data = await docClient.send(new QueryCommand(params));
        // Filter in memory for records that actually have submissions
        const withSubs = (data.Items || []).filter(r => r.submissionTitle || r.submissionUrl);
        
        res.json(withSubs);
    } catch (err) {
        console.error("Submissions Fetch Error", err);
        res.status(500).json({ error: "Failed to fetch submissions" });
    }
});

// B. Get Event Statuses (Open/Closed) for Coordinator's Dept
app.get('/api/coordinator/event-controls', isAuthenticated('coordinator'), async (req, res) => {
    const userDept = req.session.user.dept;
    try {
        // 1. Get All Events
        const eventData = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        const allEvents = eventData.Items || [];

        // 2. Filter for Dept
        const myEvents = allEvents.filter(e => e.departments && e.departments.includes(userDept));

        // 3. Get Status Overrides from Lakshya_EventStatus
        // We scan because Query requires partition key, and we want all statuses for this dept
        // Optimization: In production, query by GSI on 'deptName' if volume is high.
        // For now, we fetch statuses one by one or scan table (Scan is okay for small table)
        const statusData = await docClient.send(new ScanCommand({ TableName: 'Lakshya_EventStatus' }));
        const statusMap = {};
        (statusData.Items || []).forEach(s => {
            if (s.deptName === userDept) statusMap[s.eventId] = s.isOpen;
        });

        // 4. Merge
        const result = myEvents.map(e => ({
            eventId: e.eventId,
            title: e.title,
            isOpen: statusMap[e.eventId] !== false // Default to true if no record exists
        }));

        res.json(result);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Failed to load controls" });
    }
});

// C. Toggle Event Status
app.post('/api/coordinator/toggle-event', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId, isOpen } = req.body;
    const userDept = req.session.user.dept;
    const statusId = `${eventId}#${userDept}`;

    const params = {
        TableName: 'Lakshya_EventStatus',
        Item: {
            statusId,
            eventId,
            deptName: userDept,
            isOpen, // boolean
            updatedAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: `Event ${isOpen ? 'Opened' : 'Closed'} successfully.` });
    } catch (e) {
        res.status(500).json({ error: "Update failed" });
    }
});

// --- ROUTE HANDLERS FOR NEW HTML PAGES ---
app.get('/coordinator/view-submissions', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/submissions.html'));
});
app.get('/coordinator/event-control', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/event-control.html'));
});


///

// ==========================================
//          CHATBOT LOGIC START
// ==========================================

// 1. Define Custom FAQs (Rule-Based Knowledge)
const customFAQs = [
    { 
        keywords: ['accommodation', 'stay', 'room', 'hostel', 'dorm'], 
        answer: "Accommodation is provided in the college hostels for ₹200/day. You can request it via the Coordinator.",
        action: { text: "Contact Coordinator", link: "/contact" }
    },
    { 
        keywords: ['certificate', 'participation', 'download'], 
        answer: "Certificates will be available for download in the 'Certificates' tab 24 hours after the event ends.",
        action: { text: "Go to Certificates", link: "/participant/certificates" }
    },
    { 
        keywords: ['refund', 'cancel', 'money back', 'return'], 
        answer: "Registration fees are strictly non-refundable. However, you can transfer your ticket to a teammate by contacting support.",
        action: null
    },
    { 
        keywords: ['food', 'lunch', 'canteen', 'dinner', 'eat'], 
        answer: "Food coupons are provided in event kit, valid at the food stalls during fest.",
        action: null
    },
    { 
        keywords: ['location', 'address', 'where', 'map', 'venue'], 
        answer: "The fest is held at the Main Campus, Admin Block. You can find the Google Maps link on our Contact page.",
        action: { text: "View Map", link: "/contact" }
    },
    { 
        keywords: ['timing', 'schedule', 'when', 'start', 'time'], 
        answer: "Events generally start at 9:00 AM sharp. Please check the specific event details page for exact timings.",
        action: { text: "Check Events", link: "/events" }
    },
    { 
        keywords: ['team', 'size', 'group', 'member'], 
        answer: "Team sizes vary by event (usually 1-4 members). You can add team members during the registration process.",
        action: null
    },
    { 
        keywords: ['contact', 'help', 'issue', 'problem', 'support'],
        answer: "You can reach the coordinators at support@testify-lac.com or visit the Committee page.",
        action: { text: "Committee Info", link: "/committee" }
    }
];

// 2. Chatbot API Endpoint
app.post('/api/chat', async (req, res) => {
    const { message } = req.body;
    // Check if session exists, otherwise treat as guest
    const user = req.session.user || null; 
    const msg = message.toLowerCase();
    
    let reply = "I'm not sure about that. Try asking about 'accommodation', 'certificates', or 'events'.";
    let actions = []; 

    try {
        // --- A. GREETINGS ---
        if (msg.match(/\b(hi|hello|hey|greetings)\b/)) {
            reply = `Hello ${user ? user.name.split(' ')[0] : 'there'}! I can help you with Event Details, Registration Status, or General FAQs.`;
            actions = [
                { text: "Browse Events", val: "show events" },
                { text: "Accommodation?", val: "accommodation details" },
                { text: "My Status", val: "my registration status" }
            ];
        }

        // --- B. CUSTOM FAQ MATCHING (Rule-Based) ---
        else {
            // Check if the message matches any keyword in our FAQ list
            const matchedFAQ = customFAQs.find(faq => 
                faq.keywords.some(keyword => msg.includes(keyword))
            );

            if (matchedFAQ) {
                reply = matchedFAQ.answer;
                if (matchedFAQ.action) actions.push(matchedFAQ.action);
            }
            
            // --- C. DYNAMIC DATABASE QUERIES ---
            
            // 1. Query Events (Keywords: event, list, show, technical)
            else if (msg.includes('event') || msg.includes('list') || msg.includes('show')) {
                // Fetch events from DB
                const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
                const events = data.Items || [];
                
                if (msg.includes('technical') || msg.includes('major')) {
                    const tech = events.filter(e => e.type === 'Major' || e.type === 'Special');
                    reply = `We have ${tech.length} major technical events available!`;
                    actions = [{ text: "View Technical Events", link: "/events" }];
                } else {
                    reply = `We have ${events.length} total events exciting events lined up! You can browse them all below.`;
                    actions = [{ text: "Go to Events Page", link: "/events" }];
                }
            }

            // 2. User Specific Status (Keywords: my, status, register)
            else if (msg.includes('my') || msg.includes('status') || msg.includes('register')) {
                if (!user) {
                    reply = "You need to login to check your specific registration status.";
                    actions = [{ text: "Login Now", link: "/login" }];
                } else {
                    const params = {
                        TableName: 'Lakshya_Registrations',
                        IndexName: 'StudentIndex',
                        KeyConditionExpression: 'studentEmail = :email',
                        ExpressionAttributeValues: { ':email': user.email }
                    };
                    const data = await docClient.send(new QueryCommand(params));
                    const regs = data.Items || [];
                    
                    if (regs.length === 0) {
                        reply = "You haven't registered for any events yet.";
                        actions = [{ text: "Register Now", link: "/events" }];
                    } else {
                        const paidCount = regs.filter(r => r.paymentStatus === 'COMPLETED').length;
                        reply = `You are registered for ${regs.length} events (${paidCount} Confirmed/Paid). Check your dashboard for full details.`;
                        actions = [{ text: "View Dashboard", link: "/participant/dashboard" }];
                    }
                }
            }
        }

        res.json({ reply, actions });

    } catch (err) {
        console.error("Chat Error:", err);
        // Fallback in case of DB error
        res.json({ 
            reply: "My brain is having a glitch (Database Error). Try again later.", 
            actions: [{ text: "Refresh Page", link: "#" }] 
        });
    }
});
const PORT = process.env.PORT || 3000;

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(` LAKSHYA 2K26 Server running on http://localhost:${PORT}`);
    });
}

module.exports = app;
