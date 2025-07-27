require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 5001;

app.use(express.json());

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://luju-mood-calendar.vercel.app',
      'http://localhost:3000',
      'http://127.0.0.1:3000'
    ];
    
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Max-Age', '86400');
  next();
});

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
    process.exit(-1);
});

pool.query('SELECT NOW()')
    .then(() => console.log('Successfully connected to Neon PostgreSQL!'))
    .catch(err => console.error('Database connection error:', err));

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.warn('WARNING: JWT_SECRET environment variable is not set. Please set a strong, random value in your .env file for production!');
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.log('No authentication token provided.');
        return res.status(401).json({ message: 'Authentication token required.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

app.post('/api/register', async (req, res) => {
    const { username, password, role, partnerId } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ message: 'Username, password, and role are required.' });
    }
    if (role === 'supporter' && !partnerId) {
        return res.status(400).json({ message: 'Supporter role requires a partner ID.' });
    }
    if (role === 'owner' && partnerId) {
        return res.status(400).json({ message: 'Owner role cannot have a partner ID during registration.' });
    }

    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ message: 'Username already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        let userOwnerId = null;
        let partnerOwnerId = partnerId || null;

        if (role === 'owner') {
            const result = await pool.query(
                'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
                [username, hashedPassword, role]
            );
            userOwnerId = result.rows[0].id;
            await pool.query('UPDATE users SET owner_id = $1 WHERE id = $2', [userOwnerId, userOwnerId]);

        } else {
            const partnerUser = await pool.query('SELECT id, role FROM users WHERE owner_id = $1 AND role = \'owner\'', [partnerId]);
            if (partnerUser.rows.length === 0) {
                return res.status(400).json({ message: 'Invalid partner ID. Partner must be an existing owner.' });
            }
            const result = await pool.query(
                'INSERT INTO users (username, password_hash, role, owner_id) VALUES ($1, $2, $3, $4) RETURNING id',
                [username, hashedPassword, role, partnerId]
            );
            userOwnerId = result.rows[0].id;
        }

        const user = {
            id: userOwnerId,
            username: username,
            role: role,
            ownerId: role === 'owner' ? userOwnerId : partnerOwnerId
        };

        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({ message: 'User registered successfully!', token, user });

    } catch (error) {
        console.error('Error during registration:', error);
        if (error.code === '23505') {
            return res.status(409).json({ message: 'Username already exists.' });
        }
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const result = await pool.query('SELECT id, username, password_hash, role, owner_id FROM users WHERE username = $1', [username]);
        const userDb = result.rows[0];

        if (!userDb) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isPasswordValid = await bcrypt.compare(password, userDb.password_hash);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const user = {
            id: userDb.id,
            username: userDb.username,
            role: userDb.role,
            ownerId: userDb.owner_id
        };

        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '24h' });

        res.json({ message: 'Logged in successfully!', token, user });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});

app.get('/api/mood-entries', authenticateToken, async (req, res) => {
    const { ownerId, role } = req.user;

    if (!ownerId) {
        return res.status(400).json({ message: 'Owner ID not found for this user.' });
    }

    try {
        let query;
        let queryParams;

        if (role === 'supporter') {
            query = 'SELECT * FROM mood_entries WHERE owner_id = $1 AND is_shared = true ORDER BY entry_date DESC';
            queryParams = [ownerId];
        } else {
            query = 'SELECT * FROM mood_entries WHERE owner_id = $1 ORDER BY entry_date DESC';
            queryParams = [ownerId];
        }

        const result = await pool.query(query, queryParams);

        const moodEntriesMap = {};
        result.rows.forEach(entry => {
            const dateKey = entry.entry_date.toISOString().split('T')[0];
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
        res.json(moodEntriesMap);
    } catch (error) {
        console.error('Error fetching mood entries:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.post('/api/mood-entries', authenticateToken, async (req, res) => {
    const { dateKey, mood, energy, anxiety, sleep, journalText, tags, comments, reactions, isShared } = req.body;
    const ownerId = req.user.ownerId;

    if (!ownerId || !dateKey || mood === undefined) {
        return res.status(400).json({ message: 'Owner ID, date, and mood are required.' });
    }
    
    if (req.user.role !== 'owner') {
        return res.status(403).json({ message: 'Only owners can create or update mood entries.' });
    }

    if (mood < 1 || mood > 5 || energy < 1 || energy > 5 || anxiety < 1 || anxiety > 5 || sleep < 1 || sleep > 5) {
        return res.status(400).json({ message: 'Mood values must be between 1 and 5.' });
    }

    try {
        const existingEntry = await pool.query(
            'SELECT * FROM mood_entries WHERE owner_id = $1 AND entry_date = $2',
            [ownerId, dateKey]
        );

        if (existingEntry.rows.length > 0) {
            const result = await pool.query(
                `UPDATE mood_entries
                 SET mood = $1, energy = $2, anxiety = $3, sleep = $4, journal_text = $5, tags = $6,
                     comments = $7, reactions = $8, is_shared = $9, updated_at = NOW()
                 WHERE owner_id = $10 AND entry_date = $11 RETURNING *`,
                [mood, energy, anxiety, sleep, journalText, tags, comments, reactions, isShared, ownerId, dateKey]
            );
            
            const updatedEntry = result.rows[0];
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
            const result = await pool.query(
                `INSERT INTO mood_entries (owner_id, entry_date, mood, energy, anxiety, sleep, journal_text, tags, comments, reactions, is_shared, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW()) RETURNING *`,
                [ownerId, dateKey, mood, energy, anxiety, sleep, journalText, tags, comments, reactions, isShared]
            );
            
            const newEntry = result.rows[0];
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
        if (error.code === '23505') {
            return res.status(409).json({ message: 'An entry for this date already exists for this owner.' });
        }
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.delete('/api/mood-entries/:dateKey', authenticateToken, async (req, res) => {
    const { dateKey } = req.params;
    const ownerId = req.user.ownerId;

    if (req.user.role !== 'owner') {
        return res.status(403).json({ message: 'Only owners can delete entries.' });
    }

    try {
        const result = await pool.query(
            'DELETE FROM mood_entries WHERE owner_id = $1 AND entry_date = $2 RETURNING *',
            [ownerId, dateKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Mood entry not found or not authorized.' });
        }
        res.status(200).json({ message: 'Entry deleted successfully' });
    } catch (error) {
        console.error('Error deleting mood entry:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.post('/api/mood-entries/:dateKey/comments', authenticateToken, async (req, res) => {
    const { dateKey } = req.params;
    const { commentText } = req.body;
    const { id: commenterId, username: commenterUsername, role: commenterRole, ownerId: currentUserOwnerId } = req.user;

    if (!commentText) {
        return res.status(400).json({ message: 'Comment text is required.' });
    }

    try {
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

        if (commenterRole !== 'supporter') {
            return res.status(403).json({ message: 'Only supporters can add comments.' });
        }
        
        if (entryOwnerId !== currentUserOwnerId) {
            return res.status(403).json({ message: 'Not authorized to comment on this entry.' });
        }
        
        if (!isShared) {
            return res.status(403).json({ message: 'Cannot comment on non-shared entries.' });
        }

        const newComment = {
            userId: commenterId,
            username: commenterUsername,
            text: commentText,
            timestamp: new Date().toISOString()
        };

        const updatedComments = [...existingComments, newComment];

        const updateResult = await pool.query(
            'UPDATE mood_entries SET comments = $1::jsonb WHERE entry_date = $2 RETURNING *',
            [JSON.stringify(updatedComments), dateKey]
        );

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

app.post('/api/mood-entries/:dateKey/reactions', authenticateToken, async (req, res) => {
    const { dateKey } = req.params;
    const { reactionType } = req.body;
    const { id: reactorId, username: reactorUsername, role: reactorRole, ownerId: currentUserOwnerId } = req.user;

    if (!reactionType) {
        return res.status(400).json({ message: 'Reaction type is required.' });
    }

    try {
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

        if (reactorRole !== 'supporter') {
            return res.status(403).json({ message: 'Only supporters can add reactions.' });
        }
        
        if (entryOwnerId !== currentUserOwnerId) {
            return res.status(403).json({ message: 'Not authorized to react to this entry.' });
        }
        
        if (!isShared) {
            return res.status(403).json({ message: 'Cannot react to non-shared entries.' });
        }

        const existingReactionIndex = existingReactions.findIndex(
            r => r.userId === reactorId && r.type === reactionType
        );

        let updatedReactions;
        if (existingReactionIndex > -1) {
            updatedReactions = existingReactions.filter((_, index) => index !== existingReactionIndex);
        } else {
            const newReaction = {
                userId: reactorId,
                username: reactorUsername,
                type: reactionType,
                timestamp: new Date().toISOString()
            };
            updatedReactions = [...existingReactions, newReaction];
        }

        const updateResult = await pool.query(
            'UPDATE mood_entries SET reactions = $1::jsonb WHERE entry_date = $2 RETURNING *',
            [JSON.stringify(updatedReactions), dateKey]
        );

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

app.use((error, req, res, next) => {
  if (error.message === 'Not allowed by CORS') {
    return res.status(403).json({
      message: 'CORS policy violation',
      origin: req.get('Origin')
    });
  }
  next(error);
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    console.log(`Access http://localhost:${port}/api`);
});

module.exports = app;