// frontend/moodtracker.js

const API_BASE_URL = 'http://localhost:5001/api';

class MoodTracker {
    constructor() {
        this.currentUser = null;
        this.moodEntries = {};
        this.currentDate = new Date();
        this.selectedDate = null;
        this.currentTags = [];
        this.predefinedTags = ['Relationship', 'Stress', 'School', 'Work', 'Goals', 'Depression', 'Family', 'Friends', 'Health', 'Hobbies', 'Travel', 'Finance', 'Personal Growth', 'Gratitude', 'Mindfulness', 'Exercise', 'Diet', 'Sleep', 'Therapy', 'Meditation', 'Nature', 'Creativity'];

        this.initializeApp();
        this.setupEventListeners();
    }

    async sendApiRequest(endpoint, method = 'GET', data = null) {
        const token = localStorage.getItem('moodTracker_jwtToken');
        const headers = {
            'Content-Type': 'application/json',
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const options = {
            method: method,
            headers: headers,
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, options);

            if (!response.ok) {
                const errorData = await response.json();
                if (response.status === 401 || response.status === 403) {
                    this.logout();
                    throw new Error(errorData.message || 'Authentication failed. Please log in again.');
                }
                throw new Error(errorData.message || 'Something went wrong with the API request.');
            }

            if (response.status === 204) {
                return true;
            }
            return await response.json();

        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    async initializeApp() {
        const storedToken = localStorage.getItem('moodTracker_jwtToken');
        const storedUser = localStorage.getItem('moodTracker_currentUser');

        if (storedToken && storedUser) {
            try {
                this.currentUser = JSON.parse(storedUser);
                await this.loadMoodEntries();
                this.showMainApp();
            } catch (error) {
                console.warn('Stored token or user invalid, logging out:', error.message);
                this.logout();
            }
        } else {
            this.showLoginScreen();
            this.toggleRegisterMode(false); 
        }
    }

    async loadMoodEntries() {
        try {
            const entries = await this.sendApiRequest('/mood-entries', 'GET');
            this.moodEntries = entries;
            this.updateCalendar();
        } catch (error) {
            console.error('Failed to load mood entries:', error);
            alert('Failed to load mood entries. Please try logging in again.');
            this.logout();
        }
    }

    setupEventListeners() {
        document.getElementById('loginForm').addEventListener('submit', this.handleLoginSubmit.bind(this));
        document.getElementById('registerLink').addEventListener('click', () => this.toggleRegisterMode(true));
        document.getElementById('loginLink').addEventListener('click', () => this.toggleRegisterMode(false));

        document.getElementById('prevMonthBtn').addEventListener('click', () => this.changeMonth(-1));
        document.getElementById('nextMonthBtn').addEventListener('click', () => this.changeMonth(1));
        document.getElementById('currentMonthYear').addEventListener('click', () => this.goToToday());

        document.getElementById('moodModal').addEventListener('click', (e) => {
            if (e.target.id === 'moodModal') {
                this.closeModal();
            }
        });
        document.getElementById('closeModalBtn').addEventListener('click', this.closeModal.bind(this));
        document.getElementById('saveEntryBtn').addEventListener('click', this.saveEntry.bind(this));
        document.getElementById('deleteEntryBtn').addEventListener('click', this.deleteEntry.bind(this));

        document.getElementById('addTagBtn').addEventListener('click', this.addCustomTag.bind(this));
        document.getElementById('tagInput').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.addCustomTag();
            }
        });
        this.setupTagSelectionListeners();

        document.getElementById('logoutBtn').addEventListener('click', this.logout.bind(this));

        document.getElementById('addCommentBtn').addEventListener('click', this.addComment.bind(this));
        document.getElementById('addReactionBtn').addEventListener('click', this.addReaction.bind(this));
    }

    async handleLoginSubmit(event) {
        event.preventDefault();
        const usernameInput = document.getElementById('usernameInput');
        const passwordInput = document.getElementById('passwordInput');
        const roleSelect = document.getElementById('roleSelect');
        const partnerIdInput = document.getElementById('partnerIdInput');
        
        const isRegisterMode = document.getElementById('registerLink').classList.contains('active');

        const username = usernameInput.value;
        const password = passwordInput.value;
        const role = roleSelect.value;
        const partnerId = partnerIdInput.value.trim();

        try {
            let responseData;
            if (isRegisterMode) {
                if (!role) {
                    alert('Please select a role for registration.');
                    return;
                }
                if (role === 'supporter' && !partnerId) {
                    alert('Please enter a Partner\'s Unique ID if you are a supporter.');
                    return;
                }
                responseData = await this.registerUser(username, password, role, role === 'supporter' ? partnerId : null);
                alert('Registration successful! You are now logged in.');
            } else {
                responseData = await this.loginUser(username, password);
                alert('Login successful!');
            }

            this.currentUser = responseData.user;
            localStorage.setItem('moodTracker_currentUser', JSON.stringify(responseData.user));
            localStorage.setItem('moodTracker_jwtToken', responseData.token);
            document.getElementById('loggedInUser').textContent = this.currentUser.username;

            await this.loadMoodEntries();
            this.showMainApp();

        } catch (error) {
            console.error('Authentication error:', error);
            alert(`Authentication failed: ${error.message}`);
        }
    }

    async registerUser(username, password, role, partnerId) {
        return this.sendApiRequest('/register', 'POST', { username, password, role, partnerId });
    }

    async loginUser(username, password) {
        return this.sendApiRequest('/login', 'POST', { username, password });
    }

    showLoginScreen() {
        document.getElementById('loginScreen').classList.remove('hidden');
        document.getElementById('mainApp').classList.add('hidden');
    }

    showMainApp() {
        document.getElementById('loginScreen').classList.add('hidden');
        document.getElementById('mainApp').classList.remove('hidden');
        this.currentDate = new Date();
        this.updateCalendar();
    }

    logout() {
        this.currentUser = null;
        this.moodEntries = {};
        localStorage.removeItem('moodTracker_currentUser');
        localStorage.removeItem('moodTracker_jwtToken');
        alert('You have been logged out.');
        this.showLoginScreen();
    }

    toggleRegisterMode(isRegister) {
        const loginTitle = document.getElementById('loginTitle');
        const registerLink = document.getElementById('registerLink');
        const loginLink = document.getElementById('loginLink');
        const partnerIdGroup = document.getElementById('partnerIdGroup');
        const passwordInput = document.getElementById('passwordInput');
        const roleSelect = document.getElementById('roleSelect');
        const loginBtn = document.getElementById('loginBtn');

        if (isRegister) {
            loginTitle.textContent = 'Register New Account';
            registerLink.classList.add('active');
            loginLink.classList.remove('active');
            loginBtn.textContent = 'Register';
            
            roleSelect.value = '';
            partnerIdGroup.classList.add('hidden');
            roleSelect.parentNode.classList.remove('hidden');
            roleSelect.addEventListener('change', this.handleRoleChange.bind(this));

            passwordInput.setAttribute('placeholder', 'Create your password');

        } else {
            loginTitle.textContent = 'Login to see the Calendar';
            registerLink.classList.remove('active');
            loginLink.classList.add('active');
            loginBtn.textContent = 'Login';
            
            roleSelect.value = '';
            roleSelect.parentNode.classList.add('hidden');
            partnerIdGroup.classList.add('hidden');
            roleSelect.removeEventListener('change', this.handleRoleChange);

            passwordInput.setAttribute('placeholder', 'Enter your password');
        }
    }

    handleRoleChange() {
        const roleSelect = document.getElementById('roleSelect');
        const partnerIdGroup = document.getElementById('partnerIdGroup');
        if (roleSelect.value === 'supporter') {
            partnerIdGroup.classList.remove('hidden');
        } else {
            partnerIdGroup.classList.add('hidden');
        }
    }

    formatDateKey(date) {
        const year = date.getFullYear();
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    updateCalendar() {
        const monthYearDisplay = document.getElementById('currentMonthYear');
        const daysContainer = document.getElementById('daysContainer');
        const loggedInUserSpan = document.getElementById('loggedInUser');

        const year = this.currentDate.getFullYear();
        const month = this.currentDate.getMonth();

        const firstDayOfMonth = new Date(year, month, 1);
        const lastDayOfMonth = new Date(year, month + 1, 0);
        const numDaysInMonth = lastDayOfMonth.getDate();

        const firstDayOfWeek = firstDayOfMonth.getDay();

        monthYearDisplay.textContent = this.currentDate.toLocaleString('default', {
            month: 'long',
            year: 'numeric'
        });
        daysContainer.innerHTML = '';

        if (this.currentUser) {
            loggedInUserSpan.textContent = this.currentUser.username;
        } else {
            loggedInUserSpan.textContent = '';
        }

        for (let i = 0; i < firstDayOfWeek; i++) {
            const emptyDay = document.createElement('div');
            emptyDay.classList.add('day', 'empty');
            daysContainer.appendChild(emptyDay);
        }

        for (let day = 1; day <= numDaysInMonth; day++) {
            const date = new Date(year, month, day);
            const dateKey = this.formatDateKey(date);
            const dayElement = document.createElement('div');
            dayElement.classList.add('day');
            dayElement.textContent = day;
            dayElement.dataset.dateKey = dateKey;

            const todayKey = this.formatDateKey(new Date());
            if (dateKey === todayKey) {
                dayElement.classList.add('current-day');
            }

            if (this.moodEntries[dateKey]) {
                dayElement.classList.add('has-entry');
                const mood = this.moodEntries[dateKey].mood;
                if (mood !== undefined) {
                    dayElement.classList.add(`mood-${mood}`);
                }
            }

            dayElement.addEventListener('click', () => this.openModal(date));
            daysContainer.appendChild(dayElement);
        }

        this.updateStreakDisplay();
    }

    changeMonth(offset) {
        this.currentDate.setMonth(this.currentDate.getMonth() + offset);
        this.updateCalendar();
    }

    goToToday() {
        this.currentDate = new Date();
        this.updateCalendar();
        this.openModal(new Date());
    }

    openModal(date) {
        this.selectedDate = date;
        const dateKey = this.formatDateKey(date);
        document.getElementById('modalDate').textContent = date.toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });

        const entry = this.moodEntries[dateKey];

        // Set dropdown values based on existing entry or defaults
        document.getElementById('moodSelect').value = entry ? entry.mood : '';
        document.getElementById('energySelect').value = entry ? entry.energy : '';
        document.getElementById('anxietySelect').value = entry ? entry.anxiety : '';
        document.getElementById('sleepSelect').value = entry ? entry.sleep : '';
        document.getElementById('journalText').value = entry ? entry.journalText : '';
        this.currentTags = entry ? [...entry.tags || []] : [];
        this.renderTags();

        const saveEntryBtn = document.getElementById('saveEntryBtn');
        const deleteEntryBtn = document.getElementById('deleteEntryBtn');
        const commentForm = document.getElementById('commentForm');
        const reactionForm = document.getElementById('reactionForm');
        const sharingSection = document.getElementById('sharingSection');

        sharingSection.classList.add('hidden');
        commentForm.classList.add('hidden');
        reactionForm.classList.add('hidden');

        if (this.currentUser.role === 'owner') {
            saveEntryBtn.classList.remove('hidden');
            sharingSection.classList.remove('hidden');
            document.getElementById('shareWithPartnerCheckbox').checked = entry ? (entry.isShared || false) : false;
            
            if (entry && entry.ownerId === this.currentUser.ownerId) {
                deleteEntryBtn.classList.remove('hidden');
            } else {
                deleteEntryBtn.classList.add('hidden');
            }
        } else if (this.currentUser.role === 'supporter') {
            saveEntryBtn.classList.add('hidden');
            deleteEntryBtn.classList.add('hidden');
            
            if (entry && entry.isShared) {
                commentForm.classList.remove('hidden');
                reactionForm.classList.remove('hidden');
            }
        } else {
            saveEntryBtn.classList.add('hidden');
            deleteEntryBtn.classList.add('hidden');
            commentForm.classList.add('hidden');
            reactionForm.classList.add('hidden');
            sharingSection.classList.add('hidden');
        }

        this.renderComments(entry ? entry.comments : []);
        this.renderReactions(entry ? entry.reactions : []);

        document.getElementById('moodModal').classList.remove('hidden');
    }

    closeModal() {
        document.getElementById('moodModal').classList.add('hidden');
        this.selectedDate = null;
        this.currentTags = [];
        this.renderTags();
        this.updateCalendar();
    }

    async saveEntry() {
        if (!this.selectedDate || !this.currentUser || this.currentUser.role !== 'owner') {
            alert('Error: You must be an owner and select a date to save an entry.');
            return;
        }

        const dateKey = this.formatDateKey(this.selectedDate);
        const mood = parseInt(document.getElementById('moodSelect').value);
        const energy = parseInt(document.getElementById('energySelect').value);
        const anxiety = parseInt(document.getElementById('anxietySelect').value);
        const sleep = parseInt(document.getElementById('sleepSelect').value);
        const journalText = document.getElementById('journalText').value.trim();
        const isShared = document.getElementById('shareWithPartnerCheckbox').checked;

        // Validate that all fields are selected
        if (!mood || !energy || !anxiety || !sleep) {
            alert('Please select values for all mood indicators (Mood, Energy, Anxiety, Sleep).');
            return;
        }

        const entryData = {
            dateKey: dateKey,
            mood: mood,
            energy: energy,
            anxiety: anxiety,
            sleep: sleep,
            journalText: journalText,
            tags: this.currentTags,
            isShared: isShared,
            comments: this.moodEntries[dateKey]?.comments || [],
            reactions: this.moodEntries[dateKey]?.reactions || []
        };

        try {
            const result = await this.sendApiRequest('/mood-entries', 'POST', entryData);
            this.moodEntries[dateKey] = {
                ...result.entry,
                dateKey: dateKey,
            };
            alert('Mood entry saved successfully!');
            this.closeModal();
            this.updateCalendar();
        } catch (error) {
            console.error('Failed to save mood entry:', error);
            alert(`Failed to save mood entry: ${error.message}`);
        }
    }

    async deleteEntry() {
        if (!this.selectedDate || !this.currentUser || this.currentUser.role !== 'owner') {
            alert('Error: You must be an owner and select an entry to delete.');
            return;
        }

        const dateKey = this.formatDateKey(this.selectedDate);
        const entryToDelete = this.moodEntries[dateKey];

        if (!entryToDelete || entryToDelete.ownerId !== this.currentUser.ownerId) {
            alert('Error: No entry found for this date or you do not have permission to delete it.');
            return;
        }

        if (confirm('Are you sure you want to delete this mood entry?')) {
            try {
                await this.sendApiRequest(`/mood-entries/${dateKey}`, 'DELETE');
                delete this.moodEntries[dateKey];
                alert('Mood entry deleted successfully!');
                this.closeModal();
                this.updateCalendar();
            } catch (error) {
                console.error('Failed to delete mood entry:', error);
                alert(`Failed to delete mood entry: ${error.message}`);
            }
        }
    }

    addCustomTag() {
        const tagInput = document.getElementById('tagInput');
        let tagText = tagInput.value.trim();

        if (tagText && !this.currentTags.includes(tagText)) {
            if (tagText.length > 0 && tagText[0] === tagText[0].toLowerCase()) {
                tagText = tagText.charAt(0).toUpperCase() + tagText.slice(1);
            }
            this.currentTags.push(tagText);
            this.renderTags();
            tagInput.value = '';
        }
    }

    addPredefinedTag(tag) {
        if (!this.currentTags.includes(tag)) {
            this.currentTags.push(tag);
            this.renderTags();
        }
    }

    removeTag(tagText) {
        this.currentTags = this.currentTags.filter(tag => tag !== tagText);
        this.renderTags();
    }

    renderTags() {
        const tagsDisplay = document.getElementById('tagsDisplay');
        tagsDisplay.innerHTML = '';
        this.currentTags.forEach(tag => {
            const tagSpan = document.createElement('span');
            tagSpan.classList.add('tag');
            tagSpan.innerHTML = `${tag} <span class="tagRemove">&times;</span>`;
            tagsDisplay.appendChild(tagSpan);
        });

        const predefinedTagsContainer = document.getElementById('predefinedTags');
        predefinedTagsContainer.innerHTML = '';
        this.predefinedTags.forEach(tag => {
            const tagBtn = document.createElement('button');
            tagBtn.classList.add('tag-btn');
            tagBtn.textContent = tag;
            tagBtn.addEventListener('click', () => this.addPredefinedTag(tag));
            predefinedTagsContainer.appendChild(tagBtn);
        });
    }

    updateStreakDisplay() {
        const streakDisplay = document.getElementById('streakDisplay');
        const streak = this.calculateCurrentStreak();
        streakDisplay.textContent = `Current Streak: ${streak} day${streak === 1 ? '' : 's'}`;
    }

    calculateCurrentStreak() {
        if (Object.keys(this.moodEntries).length === 0) {
            return 0;
        }

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        let streak = 0;
        let currentDate = new Date(today);
        const relevantEntryDates = new Set(Object.keys(this.moodEntries));

        let hasTodayEntry = relevantEntryDates.has(this.formatDateKey(today));

        if (hasTodayEntry) {
            while (relevantEntryDates.has(this.formatDateKey(currentDate))) {
                streak++;
                currentDate.setDate(currentDate.getDate() - 1);
            }
        } else {
            currentDate.setDate(currentDate.getDate() - 1);
            while (relevantEntryDates.has(this.formatDateKey(currentDate))) {
                streak++;
                currentDate.setDate(currentDate.getDate() - 1);
            }
        }

        return streak;
    }

    setupTagSelectionListeners() {
        const tagContainer = document.getElementById('tagsDisplay'); 

        if (tagContainer) {
            tagContainer.addEventListener('click', (event) => {
                if (event.target.classList.contains('tagRemove')) {
                    const tagText = event.target.parentNode.textContent.replace(' ×', '');
                    this.removeTag(tagText);
                }
            });
        }
    }

    renderComments(comments) {
        const commentsList = document.getElementById('commentsList');
        commentsList.innerHTML = '';
        if (comments && comments.length > 0) {
            comments.forEach(comment => {
                const commentDiv = document.createElement('div');
                commentDiv.classList.add('comment');
                commentDiv.innerHTML = `
                    <div class="commentHeader">
                        <span class="commentAuthor">${comment.username}</span>
                        <span class="commentTime">${new Date(comment.timestamp).toLocaleDateString()} ${new Date(comment.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                    <p class="commentText">${comment.text}</p>
                `;
                commentsList.appendChild(commentDiv);
            });
        } else {
            commentsList.innerHTML = '<p class="no-comments">No comments yet.</p>';
        }
    }

    async addComment() {
        if (!this.selectedDate || !this.currentUser) {
            alert('Error: Select a date and be logged in to add a comment.');
            return;
        }
        if (this.currentUser.role === 'owner') {
             alert('Owners cannot add comments to their own entries directly through this form. Use journal text instead.');
             return;
        }

        const dateKey = this.formatDateKey(this.selectedDate);
        const commentText = document.getElementById('commentText').value.trim();

        if (!commentText) {
            alert('Please enter comment text.');
            return;
        }

        try {
            const updatedEntry = await this.sendApiRequest(`/mood-entries/${dateKey}/comments`, 'POST', { commentText });
            this.moodEntries[dateKey] = updatedEntry.entry;
            this.renderComments(updatedEntry.entry.comments);
            document.getElementById('commentText').value = '';
            alert('Comment added!');
        } catch (error) {
            console.error('Failed to add comment:', error);
            alert(`Failed to add comment: ${error.message}`);
        }
    }

    renderReactions(reactions) {
        const reactionsList = document.getElementById('reactionsList');
        reactionsList.innerHTML = '';
        if (reactions && reactions.length > 0) {
            const reactionCounts = reactions.reduce((acc, reaction) => {
                acc[reaction.type] = (acc[reaction.type] || 0) + 1;
                return acc;
            }, {});

            for (const type in reactionCounts) {
                const count = reactionCounts[type];
                const reactionBubble = document.createElement('div');
                reactionBubble.classList.add('reactionBubble');
                let emoji = type;
                switch (type) {
                    case 'heart': emoji = '❤️'; break;
                    case 'star': emoji = '⭐'; break;
                    case 'hug': emoji = '🫂'; break;
                    case 'strength': emoji = '💪'; break;
                    case 'smile': emoji = '😊'; break;
                }
                reactionBubble.innerHTML = `${emoji} <span>${count}</span>`;
                reactionsList.appendChild(reactionBubble);
            }
        } else {
            reactionsList.innerHTML = '<p class="no-reactions">No reactions yet.</p>';
        }
    }

    async addReaction() {
        if (!this.selectedDate || !this.currentUser) {
            alert('Error: Select a date and be logged in to add a reaction.');
            return;
        }
           if (this.currentUser.role === 'owner') {
             alert('Owners cannot add reactions to their own entries directly.');
             return;
        }

        const dateKey = this.formatDateKey(this.selectedDate);
        const reactionType = document.getElementById('reactionSelect').value;

        if (!reactionType) {
            alert('Please select a reaction type.');
            return;
        }

        try {
            const updatedEntry = await this.sendApiRequest(`/mood-entries/${dateKey}/reactions`, 'POST', { reactionType });
            this.moodEntries[dateKey] = updatedEntry.entry;
            this.renderReactions(updatedEntry.entry.reactions);
            document.getElementById('reactionSelect').value = '';
            alert('Reaction toggled!');
        } catch (error) {
            console.error('Failed to add reaction:', error);
            alert(`Failed to add reaction: ${error.message}`);
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new MoodTracker();
});