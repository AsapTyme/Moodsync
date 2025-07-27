// backend/index.js

// Load environment variables from .env file.
// This MUST be the very first line in the file to ensure variables are available.
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg'); // PostgreSQL client library
const bcrypt = require('bcryptjs'); // For hashing passwords
const jwt = require('jsonwebtoken'); // For JSON Web Tokens
const cors = require('cors'); // For Cross-Origin Resource Sharing
const bodyParser = require('body-parser'); // For parsing JSON request bodies

// Initialize Express app
const app = express();
// Define the port for the server. Uses environment variable PORT (for Vercel) or defaults to 5001 (for local).
const port = process.env.PORT || 5001;

// --- Middleware ---

// Enable CORS for all origins. This is temporary for local development/testing with Postman.
// For production deployment on Vercel, we will revert this to a more secure configuration
// that restricts access only to your frontend's domain.
app.use(cors());

// Parse incoming JSON request bodies.
app.use(bodyParser.json());

// --- Database Connection Pool ---
// Configure the PostgreSQL connection using the DATABASE_URL environment variable.
// This URL contains all necessary credentials for your Neon database.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        // rejectUnauthorized: false is often needed for local development with Neon's SSL.
        // In a Vercel production environment, Vercel typically handles SSL, and this might
        // not be strictly necessary or might be set to true for stricter security.
        rejectUnauthorized: false
    }
});

// Event listener for database connection errors.
pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
    // Exit the process if a critical database connection error occurs.
    process.exit(-1);
});

// Test the database connection when the server starts.
pool.query('SELECT NOW()')
    .then(() => console.log('Successfully connected to Neon PostgreSQL!'))
    .catch(err => console.error('Database connection error:', err));


// --- JWT Secret Key ---
// This secret key is used to sign and verify JSON Web Tokens.
// It should be a strong, random, and securely stored value in production.
// We are reading it from the .env file.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    // This warning helps ensure you've set your secret in the .env file.
    console.warn('WARNING: JWT_SECRET environment variable is not set. Please set a strong, random value in your .env file for production!');
}

// --- Middleware for Authentication (JWT Verification) ---
// This function verifies the JWT provided in the 'Authorization' header of incoming requests.
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // Extract the token from the "Bearer TOKEN" format.
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        // If no token is provided, return 401 Unauthorized.
        console.log('No authentication token provided.');
        return res.status(401).json({ message: 'Authentication token required.' });
    }

    // Verify the token using the JWT_SECRET.
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // If verification fails (e.g., token is invalid or expired), return 403 Forbidden.
            console.error('JWT verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        // If the token is valid, attach the decoded user payload to the request object.
        req.user = user;
        // Proceed to the next middleware or route handler.
        next();
    });
}

// --- API Endpoints ---

// 1. User Registration Endpoint
// Allows new users to register as 'owner' or 'supporter'.
app.post('/api/register', async (req, res) => {
    const { username, password, role, partnerId } = req.body;

    // Basic validation for required fields.
    if (!username || !password || !role) {
        return res.status(400).json({ message: 'Username, password, and role are required.' });
    }
    // Specific validation for 'supporter' role requiring a partnerId.
    if (role === 'supporter' && !partnerId) {
        return res.status(400).json({ message: 'Supporter role requires a partner ID.' });
    }
    // Specific validation for 'owner' role not having a partnerId during registration.
    if (role === 'owner' && partnerId) {
        return res.status(400).json({ message: 'Owner role cannot have a partner ID during registration.' });
    }

    try {
        // Check if the username already exists in the database.
        const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ message: 'Username already exists.' });
        }

        // Hash the user's password for secure storage.
        const hashedPassword = await bcrypt.hash(password, 10); // 10 salt rounds is a good default.

        let userOwnerId = null; // This will be the ID that mood entries are linked to.
        let partnerOwnerId = partnerId || null; // Stores the partner's ownerId for supporters.

        if (role === 'owner') {
            // If registering as an owner, insert the user and set their own ID as their owner_id.
            const result = await pool.query(
                'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
                [username, hashedPassword, role]
            );
            userOwnerId = result.rows[0].id; // The newly generated UUID is the user's ID.
            // Update the user's owner_id column to be their own id.
            await pool.query('UPDATE users SET owner_id = $1 WHERE id = $2', [userOwnerId, userOwnerId]);

        } else { // role === 'supporter'
            // For a supporter, validate if the provided partnerId exists and belongs to an 'owner'.
            const partnerUser = await pool.query('SELECT id, role FROM users WHERE owner_id = $1 AND role = \'owner\'', [partnerId]);
            if (partnerUser.rows.length === 0) {
                return res.status(400).json({ message: 'Invalid partner ID. Partner must be an existing owner.' });
            }
            // Insert the supporter user, linking them to the partner's ownerId.
            const result = await pool.query(
                'INSERT INTO users (username, password_hash, role, owner_id) VALUES ($1, $2, $3, $4) RETURNING id',
                [username, hashedPassword, role, partnerId] // partnerId is stored as owner_id for supporter
            );
            userOwnerId = result.rows[0].id; // The supporter's own unique user ID.
        }

        // Create a user object to be included in the JWT payload.
        const user = {
            id: userOwnerId, // The user's actual UUID from the database.
            username: username,
            role: role,
            ownerId: role === 'owner' ? userOwnerId : partnerOwnerId // Owner's own ID or partner's ID for supporter.
        };

        // Sign a JWT with the user payload. It expires in 24 hours.
        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '24h' });

        // Send a success response with the token and user information.
        res.status(201).json({ message: 'User registered successfully!', token, user });

    } catch (error) {
        console.error('Error during registration:', error);
        // Handle specific PostgreSQL unique constraint violation for username.
        if (error.code === '23505') { // PostgreSQL unique violation error code
            return res.status(409).json({ message: 'Username already exists.' });
        }
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});

// 2. User Login Endpoint
// Allows existing users to log in and receive a new JWT.
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // Basic validation for required fields.
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        // Retrieve the user from the database by username.
        const result = await pool.query('SELECT id, username, password_hash, role, owner_id FROM users WHERE username = $1', [username]);
        const userDb = result.rows[0];

        if (!userDb) {
            // If no user found, return 401 Unauthorized.
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Compare the provided password with the stored hashed password.
        const isPasswordValid = await bcrypt.compare(password, userDb.password_hash);

        if (!isPasswordValid) {
            // If passwords don't match, return 401 Unauthorized.
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Prepare user object for JWT payload (same structure as registration).
        const user = {
            id: userDb.id,
            username: userDb.username,
            role: userDb.role,
            ownerId: userDb.owner_id // This is crucial for linking to entries.
        };

        // Sign a new JWT for the logged-in user.
        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '24h' });

        // Send a success response with the new token and user information.
        res.json({ message: 'Logged in successfully!', token, user });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});

// 3. Get Mood Entries Endpoint
// Fetches all mood entries associated with the authenticated user's ownerId.
// For supporters, only returns shared entries. For owners, returns all their entries.
app.get('/api/mood-entries', authenticateToken, async (req, res) => {
    const { ownerId, role } = req.user; // Get ownerId and role from the authenticated user's JWT payload.

    if (!ownerId) {
        return res.status(400).json({ message: 'Owner ID not found for this user.' });
    }

    try {
        let query;
        let queryParams;

        if (role === 'supporter') {
            // Supporters can only see shared entries
            query = 'SELECT * FROM mood_entries WHERE owner_id = $1 AND is_shared = true ORDER BY entry_date DESC';
            queryParams = [ownerId];
        } else {
            // Owners can see all their entries
            query = 'SELECT * FROM mood_entries WHERE owner_id = $1 ORDER BY entry_date DESC';
            queryParams = [ownerId];
        }

        const result = await pool.query(query, queryParams);

        // Transform the fetched data into a map format (dateKey as key) that the frontend expects.
        const moodEntriesMap = {};
        result.rows.forEach(entry => {
            const dateKey = entry.entry_date.toISOString().split('T')[0]; // Format 'YYYY-MM-DD'.
            moodEntriesMap[dateKey] = {
                dateKey: dateKey,
                mood: entry.mood,
                energy: entry.energy,
                anxiety: entry.anxiety,
                sleep: entry.sleep,
                journalText: entry.journal_text,
                tags: entry.tags,
                comments: entry.comments,
                reactions: entry.reactions,
                isShared: entry.is_shared,
                ownerId: entry.owner_id
            };
        });
        res.json(moodEntriesMap); // Send the transformed map back to the frontend.
    } catch (error) {
        console.error('Error fetching mood entries:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// 4. Save/Update Mood Entry Endpoint
// Creates a new mood entry or updates an existing one for the authenticated user's ownerId.
// This route requires authentication and only owners can create/update entries.
app.post('/api/mood-entries', authenticateToken, async (req, res) => {
    const { dateKey, mood, energy, anxiety, sleep, journalText, tags, comments, reactions, isShared } = req.body;
    const ownerId = req.user.ownerId; // Get ownerId from the authenticated user.

    // Basic validation for essential fields.
    if (!ownerId || !dateKey || mood === undefined) {
        return res.status(400).json({ message: 'Owner ID, date, and mood are required.' });
    }
    
    // Authorization check: Only owners can create/update entries.
    if (req.user.role !== 'owner') {
        return res.status(403).json({ message: 'Only owners can create or update mood entries.' });
    }

    // Validate mood values are within expected range (1-5 for dropdown values)
    if (mood < 1 || mood > 5 || energy < 1 || energy > 5 || anxiety < 1 || anxiety > 5 || sleep < 1 || sleep > 5) {
        return res.status(400).json({ message: 'Mood values must be between 1 and 5.' });
    }

    try {
        // Check if an entry for this date and owner already exists.
        const existingEntry = await pool.query(
            'SELECT * FROM mood_entries WHERE owner_id = $1 AND entry_date = $2',
            [ownerId, dateKey]
        );

        if (existingEntry.rows.length > 0) {
            // If an entry exists, update it.
            const result = await pool.query(
                `UPDATE mood_entries
                 SET mood = $1, energy = $2, anxiety = $3, sleep = $4, journal_text = $5, tags = $6,
                     comments = $7, reactions = $8, is_shared = $9, updated_at = NOW()
                 WHERE owner_id = $10 AND entry_date = $11 RETURNING *`,
                [mood, energy, anxiety, sleep, journalText, tags, comments, reactions, isShared, ownerId, dateKey]
            );
            
            const updatedEntry = result.rows[0];
            // Transform for frontend compatibility
            const responseEntry = {
                dateKey: updatedEntry.entry_date.toISOString().split('T')[0],
                mood: updatedEntry.mood,
                energy: updatedEntry.energy,
                anxiety: updatedEntry.anxiety,
                sleep: updatedEntry.sleep,
                journalText: updatedEntry.journal_text,
                tags: updatedEntry.tags,
                comments: updatedEntry.comments,
                reactions: updatedEntry.reactions,
                isShared: updatedEntry.is_shared,
                ownerId: updatedEntry.owner_id
            };
            
            res.status(200).json({ message: 'Entry updated successfully', entry: responseEntry });
        } else {
            // If no entry exists, insert a new one.
            const result = await pool.query(
                `INSERT INTO mood_entries (owner_id, entry_date, mood, energy, anxiety, sleep, journal_text, tags, comments, reactions, is_shared, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW()) RETURNING *`,
                [ownerId, dateKey, mood, energy, anxiety, sleep, journalText, tags, comments, reactions, isShared]
            );
            
            const newEntry = result.rows[0];
            // Transform for frontend compatibility
            const responseEntry = {
                dateKey: newEntry.entry_date.toISOString().split('T')[0],
                mood: newEntry.mood,
                energy: newEntry.energy,
                anxiety: newEntry.anxiety,
                sleep: newEntry.sleep,
                journalText: newEntry.journal_text,
                tags: newEntry.tags,
                comments: newEntry.comments,
                reactions: newEntry.reactions,
                isShared: newEntry.is_shared,
                ownerId: newEntry.owner_id
            };
            
            res.status(201).json({ message: 'Entry created successfully', entry: responseEntry });
        }
    } catch (error) {
        console.error('Error saving mood entry:', error);
        // Handle specific PostgreSQL unique constraint violation for owner_id and entry_date.
        if (error.code === '23505') {
            return res.status(409).json({ message: 'An entry for this date already exists for this owner.' });
        }
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// 5. Delete Mood Entry Endpoint
// Deletes a specific mood entry for the authenticated owner.
// This route requires authentication and only owners can delete their entries.
app.delete('/api/mood-entries/:dateKey', authenticateToken, async (req, res) => {
    const { dateKey } = req.params;
    const ownerId = req.user.ownerId; // Get ownerId from the authenticated user.

    // Authorization check: Only 'owner' role can delete entries.
    if (req.user.role !== 'owner') {
        return res.status(403).json({ message: 'Only owners can delete entries.' });
    }

    try {
        // Delete the entry from the database.
        const result = await pool.query(
            'DELETE FROM mood_entries WHERE owner_id = $1 AND entry_date = $2 RETURNING *',
            [ownerId, dateKey]
        );

        if (result.rows.length === 0) {
            // If no rows were deleted, the entry was not found or not authorized for this owner.
            return res.status(404).json({ message: 'Mood entry not found or not authorized.' });
        }
        res.status(200).json({ message: 'Entry deleted successfully' });
    } catch (error) {
        console.error('Error deleting mood entry:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// 6. Add Comment to Mood Entry Endpoint
// Adds a new comment to a specific mood entry.
// This route requires authentication.
app.post('/api/mood-entries/:dateKey/comments', authenticateToken, async (req, res) => {
    const { dateKey } = req.params;
    const { commentText } = req.body;
    // Get current user's details from the JWT payload.
    const { id: commenterId, username: commenterUsername, role: commenterRole, ownerId: currentUserOwnerId } = req.user;

    if (!commentText) {
        return res.status(400).json({ message: 'Comment text is required.' });
    }

    try {
        // Fetch the existing entry to append the comment.
        const entryResult = await pool.query(
            'SELECT comments, owner_id, is_shared FROM mood_entries WHERE entry_date = $1',
            [dateKey]
        );

        if (entryResult.rows.length === 0) {
            return res.status(404).json({ message: 'Mood entry not found for this date.' });
        }

        const existingComments = entryResult.rows[0].comments || [];
        const entryOwnerId = entryResult.rows[0].owner_id;
        const isShared = entryResult.rows[0].is_shared;

        // Authorization check:
        // Only supporters can add comments, and only to shared entries of their linked owner
        if (commenterRole !== 'supporter') {
            return res.status(403).json({ message: 'Only supporters can add comments.' });
        }
        
        if (entryOwnerId !== currentUserOwnerId) {
            return res.status(403).json({ message: 'Not authorized to comment on this entry.' });
        }
        
        if (!isShared) {
            return res.status(403).json({ message: 'Cannot comment on non-shared entries.' });
        }

        // Create the new comment object.
        const newComment = {
            userId: commenterId,
            username: commenterUsername,
            text: commentText,
            timestamp: new Date().toISOString() // ISO string for consistent date/time.
        };

        // Add the new comment to the existing comments array.
        const updatedComments = [...existingComments, newComment];

        // Update the comments JSONB array in the database.
        const updateResult = await pool.query(
            'UPDATE mood_entries SET comments = $1::jsonb WHERE entry_date = $2 RETURNING *',
            [JSON.stringify(updatedComments), dateKey]
        );

        // Transform entry for frontend compatibility
        const updatedEntry = updateResult.rows[0];
        const responseEntry = {
            dateKey: updatedEntry.entry_date.toISOString().split('T')[0],
            mood: updatedEntry.mood,
            energy: updatedEntry.energy,
            anxiety: updatedEntry.anxiety,
            sleep: updatedEntry.sleep,
            journalText: updatedEntry.journal_text,
            tags: updatedEntry.tags,
            comments: updatedEntry.comments,
            reactions: updatedEntry.reactions,
            isShared: updatedEntry.is_shared,
            ownerId: updatedEntry.owner_id
        };

        res.status(200).json({ message: 'Comment added successfully', entry: responseEntry });

    } catch (error) {
        console.error('Error adding comment:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// 7. Add Reaction to Mood Entry Endpoint
// Toggles (adds or removes) a reaction for a specific mood entry.
// This route requires authentication.
app.post('/api/mood-entries/:dateKey/reactions', authenticateToken, async (req, res) => {
    const { dateKey } = req.params;
    const { reactionType } = req.body; // e.g., 'heart', 'star'.
    // Get current user's details from the JWT payload.
    const { id: reactorId, username: reactorUsername, role: reactorRole, ownerId: currentUserOwnerId } = req.user;

    if (!reactionType) {
        return res.status(400).json({ message: 'Reaction type is required.' });
    }

    try {
        // Fetch the existing entry and its ownerId.
        const entryResult = await pool.query(
            'SELECT reactions, owner_id, is_shared FROM mood_entries WHERE entry_date = $1',
            [dateKey]
        );

        if (entryResult.rows.length === 0) {
            return res.status(404).json({ message: 'Mood entry not found for this date.' });
        }

        const existingReactions = entryResult.rows[0].reactions || [];
        const entryOwnerId = entryResult.rows[0].owner_id;
        const isShared = entryResult.rows[0].is_shared;

        // Authorization check:
        // Only supporters can add reactions, and only to shared entries of their linked owner
        if (reactorRole !== 'supporter') {
            return res.status(403).json({ message: 'Only supporters can add reactions.' });
        }
        
        if (entryOwnerId !== currentUserOwnerId) {
            return res.status(403).json({ message: 'Not authorized to react to this entry.' });
        }
        
        if (!isShared) {
            return res.status(403).json({ message: 'Cannot react to non-shared entries.' });
        }

        // Check if this user already reacted with this type. If so, remove it (toggle off).
        const existingReactionIndex = existingReactions.findIndex(
            r => r.userId === reactorId && r.type === reactionType
        );

        let updatedReactions;
        if (existingReactionIndex > -1) {
            // Remove existing reaction (toggle off).
            updatedReactions = existingReactions.filter((_, index) => index !== existingReactionIndex);
        } else {
            // Add new reaction.
            const newReaction = {
                userId: reactorId,
                username: reactorUsername,
                type: reactionType,
                timestamp: new Date().toISOString()
            };
            updatedReactions = [...existingReactions, newReaction];
        }

        // Update the reactions JSONB array in the database.
        const updateResult = await pool.query(
            'UPDATE mood_entries SET reactions = $1::jsonb WHERE entry_date = $2 RETURNING *',
            [JSON.stringify(updatedReactions), dateKey]
        );

        // Transform entry for frontend compatibility
        const updatedEntry = updateResult.rows[0];
        const responseEntry = {
            dateKey: updatedEntry.entry_date.toISOString().split('T')[0],
            mood: updatedEntry.mood,
            energy: updatedEntry.energy,
            anxiety: updatedEntry.anxiety,
            sleep: updatedEntry.sleep,
            journalText: updatedEntry.journal_text,
            tags: updatedEntry.tags,
            comments: updatedEntry.comments,
            reactions: updatedEntry.reactions,
            isShared: updatedEntry.is_shared,
            ownerId: updatedEntry.owner_id
        };

        res.status(200).json({ message: 'Reaction toggled successfully', entry: responseEntry });

    } catch (error) {
        console.error('Error adding reaction:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// --- Start the Server ---
// The server listens for incoming requests on the specified port.
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    console.log(`Access http://localhost:${port}/api`);
});

// Export the Express app. This is necessary for Vercel's Serverless Functions to work.
module.exports = app;