# Bill Split App

A comprehensive bill splitting application with Google OAuth authentication, supporting multiple splitting methods, itemized bills, tax/tip handling, and debt tracking.

## Features

### 🔑 Core Features
- **Simple Bill Entry** - Add bills with subtotal, tax, and tip
- **Flexible Splitting Options**:
  - Split evenly among participants
  - Split by items (itemized bills)
  - Split by percentage
  - Split by custom amounts
  - Handle shared items (appetizers, etc.)
- **Tax & Tip Handling** - Automatic proportional distribution

### 👥 User & Group Management
- **Google OAuth Authentication** - Secure sign-in with Google
- **Group Management** - Create and manage groups of friends/family
- **Member Management** - Add members to groups by email
- **Debt Tracking** - Track running balances between users

### 📱 Mobile App Ready
- **Complete REST API** - Full API support for mobile app development
- **JSON Responses** - All endpoints return structured JSON data
- **Authentication Support** - Session-based auth for API access

## Setup

### Prerequisites
- Python 3.8+
- Google Cloud Console account for OAuth setup

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/AdamEXu/bill-split.git
   cd bill-split
   ```

2. **Create virtual environment**
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

5. **Configure Google OAuth**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add authorized redirect URI: `http://127.0.0.1:5001/auth/google/callback`
   - Copy Client ID and Client Secret to `.env` file

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Access the app**
   - Web interface: http://127.0.0.1:5001
   - API endpoints: http://127.0.0.1:5001/api/

## API Documentation

### Authentication
All API endpoints require authentication via session cookies obtained through Google OAuth.

### Endpoints

#### User
- `GET /api/user` - Get current user info

#### Groups
- `GET /api/groups` - List user's groups
- `POST /api/groups` - Create new group
- `GET /api/groups/<id>` - Get group details
- `POST /api/groups/<id>/members` - Add member to group
- `GET /api/groups/<id>/debts` - Get group debt summary

#### Bills
- `GET /api/groups/<id>/bills` - List group bills
- `POST /api/groups/<id>/bills` - Create new bill
- `GET /api/bills/<id>` - Get bill details
- `POST /api/bills/<id>/pay` - Mark bill as paid

### Example API Usage

**Create a bill with items:**
```json
POST /api/groups/{group_id}/bills
{
  "title": "Dinner at Restaurant",
  "description": "Group dinner",
  "subtotal": 80.00,
  "tax_amount": 7.20,
  "tip_amount": 16.00,
  "split_method": "itemized",
  "participants": ["user1", "user2", "user3"],
  "items": [
    {
      "name": "Pizza",
      "price": 25.00,
      "quantity": 1,
      "is_shared": true
    },
    {
      "name": "Burger",
      "price": 15.00,
      "quantity": 1,
      "participants": ["user1"]
    }
  ]
}
```

## Database Schema

The app uses SQLite with the following main tables:
- `user` - User profiles from Google OAuth
- `group` - Groups of users
- `group_member` - Group membership relationships
- `bill` - Bills with splitting information
- `bill_item` - Individual items in itemized bills
- `bill_participant` - User participation in bills
- `user_debt` - Debt tracking between users

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details
