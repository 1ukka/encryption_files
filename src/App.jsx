import { useState, useRef } from 'react'
import CryptoJS from 'crypto-js'
import './App.css'

function App() {
  const [selectedFile, setSelectedFile] = useState(null)
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState(null)
  const [isDragging, setIsDragging] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const fileInputRef = useRef(null)
  const messageTimeoutRef = useRef(null)

  // File size limit: 50MB to prevent browser crashes
  const MAX_FILE_SIZE = 50 * 1024 * 1024

  const showMessage = (type, text, duration = 3000) => {
    if (messageTimeoutRef.current) {
      clearTimeout(messageTimeoutRef.current)
    }
    setMessage({ type, text })
    if (duration > 0) {
      messageTimeoutRef.current = setTimeout(() => {
        setMessage(null)
      }, duration)
    }
  }

  const handleFileSelect = (event) => {
    const file = event.target.files[0]
    if (file) {
      // Validate file size
      if (file.size > MAX_FILE_SIZE) {
        showMessage('error', `File is too large. Maximum size is 50MB. Your file is ${formatFileSize(file.size)}.`)
        return
      }
      if (file.size === 0) {
        showMessage('error', 'Cannot encrypt empty files.')
        return
      }
      setSelectedFile(file)
      setMessage(null)
    }
  }

  const handleDragOver = (event) => {
    event.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = (event) => {
    event.preventDefault()
    setIsDragging(false)
  }

  const handleDrop = (event) => {
    event.preventDefault()
    setIsDragging(false)
    
    const file = event.dataTransfer.files[0]
    if (file) {
      // Validate file size
      if (file.size > MAX_FILE_SIZE) {
        showMessage('error', `File is too large. Maximum size is 50MB. Your file is ${formatFileSize(file.size)}.`)
        return
      }
      if (file.size === 0) {
        showMessage('error', 'Cannot encrypt empty files.')
        return
      }
      setSelectedFile(file)
      setMessage(null)
    }
  }

  const removeFile = () => {
    setSelectedFile(null)
    setPassword('')
    setMessage(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const readFileAsBase64 = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        try {
          const base64 = reader.result.split(',')[1]
          if (!base64) {
            reject(new Error('Failed to read file'))
          }
          resolve(base64)
        } catch (err) {
          reject(err)
        }
      }
      reader.onerror = () => reject(new Error('Failed to read file'))
      reader.readAsDataURL(file)
    })
  }

  const validatePassword = (pwd) => {
    if (!pwd || pwd.trim().length === 0) {
      return { valid: false, message: 'Password cannot be empty' }
    }
    if (pwd.length < 4) {
      return { valid: false, message: 'Password must be at least 4 characters long' }
    }
    return { valid: true }
  }

  const handleEncrypt = async () => {
    if (!selectedFile) {
      showMessage('error', 'Please select a file first')
      return
    }

    const passwordValidation = validatePassword(password)
    if (!passwordValidation.valid) {
      showMessage('error', passwordValidation.message)
      return
    }

    setIsProcessing(true)
    showMessage('info', 'Encrypting file...', 0)

    try {
      const base64 = await readFileAsBase64(selectedFile)
      
      // Store original filename, file type, and size for validation
      const fileData = JSON.stringify({
        version: '1.0',
        name: selectedFile.name,
        type: selectedFile.type || 'application/octet-stream',
        size: selectedFile.size,
        data: base64,
        timestamp: new Date().toISOString()
      })
      
      const encrypted = CryptoJS.AES.encrypt(fileData, password).toString()
      
      if (!encrypted) {
        throw new Error('Encryption failed')
      }
      
      // Create a blob and download
      const blob = new Blob([encrypted], { type: 'text/plain; charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${selectedFile.name}.encrypted`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      showMessage('success', 'File encrypted successfully. Download started.')
      setTimeout(() => {
        removeFile()
      }, 2000)
    } catch (error) {
      console.error('Encryption error:', error)
      showMessage('error', `Encryption failed: ${error.message || 'Unknown error'}`)
    } finally {
      setIsProcessing(false)
    }
  }

  const handleDecrypt = async () => {
    if (!selectedFile) {
      showMessage('error', 'Please select an encrypted file first')
      return
    }

    const passwordValidation = validatePassword(password)
    if (!passwordValidation.valid) {
      showMessage('error', passwordValidation.message)
      return
    }

    // Check if file has .encrypted extension
    if (!selectedFile.name.endsWith('.encrypted')) {
      showMessage('error', 'Please select a valid .encrypted file')
      return
    }

    setIsProcessing(true)
    showMessage('info', 'Decrypting file...', 0)

    try {
      const reader = new FileReader()
      
      reader.onerror = () => {
        showMessage('error', 'Failed to read encrypted file')
        setIsProcessing(false)
      }
      
      reader.onload = async (e) => {
        try {
          const encryptedContent = e.target.result
          
          if (!encryptedContent || encryptedContent.trim().length === 0) {
            throw new Error('Encrypted file is empty or invalid')
          }

          const decrypted = CryptoJS.AES.decrypt(encryptedContent, password)
          const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8)
          
          if (!decryptedStr || decryptedStr.length === 0) {
            throw new Error('Wrong password or corrupted file')
          }

          // Parse the JSON to get original file data
          let fileData
          try {
            fileData = JSON.parse(decryptedStr)
          } catch (parseError) {
            throw new Error('Invalid encrypted file format. Wrong password or corrupted file.')
          }

          // Validate required fields
          if (!fileData.data || !fileData.name) {
            throw new Error('Corrupted encrypted file - missing data')
          }
          
          // Convert base64 back to blob
          let byteCharacters
          try {
            byteCharacters = atob(fileData.data)
          } catch (atobError) {
            throw new Error('Failed to decode file data. File may be corrupted.')
          }

          const byteNumbers = new Array(byteCharacters.length)
          for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i)
          }
          const byteArray = new Uint8Array(byteNumbers)
          const blob = new Blob([byteArray], { type: fileData.type || 'application/octet-stream' })
          
          // Download the decrypted file
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = fileData.name
          document.body.appendChild(a)
          a.click()
          document.body.removeChild(a)
          URL.revokeObjectURL(url)

          showMessage('success', 'File decrypted successfully. Download started.')
          setTimeout(() => {
            removeFile()
          }, 2000)
        } catch (error) {
          console.error('Decryption error:', error)
          showMessage('error', `Decryption failed: ${error.message}`)
        } finally {
          setIsProcessing(false)
        }
      }
      
      reader.readAsText(selectedFile, 'UTF-8')
    } catch (error) {
      console.error('Decryption error:', error)
      showMessage('error', `Decryption failed: ${error.message || 'Unknown error'}`)
      setIsProcessing(false)
    }
  }

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
  }

  return (
    <div className="app-container">
      <div className="header">
        <h1>File Encryption Tool</h1>
        <p>Encrypt and decrypt files using AES-256 encryption</p>
      </div>

      <div className="encryption-section">
        {!selectedFile ? (
          <div
            className={`file-upload-area ${isDragging ? 'active' : ''}`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <div className="upload-icon">⬆</div>
            <div className="upload-text">
              <h3>Select a file or drag and drop</h3>
              <p>All file types supported (max 50MB)</p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              className="file-input"
              onChange={handleFileSelect}
            />
          </div>
        ) : (
          <div className="selected-file">
            <div className="file-info">
              <div className="file-icon">📄</div>
              <div className="file-details">
                <h4>{selectedFile.name}</h4>
                <p>{formatFileSize(selectedFile.size)}</p>
              </div>
            </div>
            <button className="remove-btn" onClick={removeFile} disabled={isProcessing}>
              Remove
            </button>
          </div>
        )}

        <div className="password-input-group">
          <label htmlFor="password">Encryption Password</label>
          <input
            id="password"
            type="password"
            placeholder="Enter a strong password (min 4 characters)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isProcessing}
            onKeyPress={(e) => {
              if (e.key === 'Enter' && selectedFile && password) {
                handleEncrypt()
              }
            }}
          />
        </div>

        <div className="action-buttons">
          <button
            className="btn btn-encrypt"
            onClick={handleEncrypt}
            disabled={!selectedFile || !password || isProcessing}
          >
            {isProcessing ? 'Processing...' : 'Encrypt File'}
          </button>
          <button
            className="btn btn-decrypt"
            onClick={handleDecrypt}
            disabled={!selectedFile || !password || isProcessing}
          >
            {isProcessing ? 'Processing...' : 'Decrypt File'}
          </button>
        </div>

        {message && (
          <div className={`${message.type}-message`}>
            {message.text}
          </div>
        )}
      </div>

      <div className="footer">
        <p>Your files are encrypted locally in your browser. No data is sent to any server.</p>
        <p style={{ marginTop: '8px', fontSize: '0.8rem' }}>
          <strong>Security Note:</strong> Keep your password safe. Files cannot be recovered without it.
        </p>
      </div>
    </div>
  )
}

export default App
