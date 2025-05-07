// Matrix style background with connecting dots
const matrixBackground = () => {
  // Canvas setup
  const canvas = document.getElementById('matrix-canvas');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  
  // Set canvas size to match window
  const resizeCanvas = () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  };
  
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);
  
  // Particle class
  class Particle {
    constructor() {
      this.reset();
    }
    
    reset() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.vx = (Math.random() - 0.5) * 0.5; // x velocity
      this.vy = (Math.random() - 0.5) * 0.5; // y velocity
      this.radius = Math.random() * 2 + 1;
      this.color = '#00FF41'; // Matrix green
      this.opacity = Math.random() * 0.5 + 0.3;
    }
    
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0, 255, 65, ${this.opacity})`;
      ctx.fill();
    }
    
    update() {
      this.x += this.vx;
      this.y += this.vy;
      
      // Bounce off edges with slight randomization
      if (this.x < 0 || this.x > canvas.width) {
        this.vx = -this.vx * (0.8 + Math.random() * 0.2);
        this.x = Math.max(0, Math.min(this.x, canvas.width));
      }
      
      if (this.y < 0 || this.y > canvas.height) {
        this.vy = -this.vy * (0.8 + Math.random() * 0.2);
        this.y = Math.max(0, Math.min(this.y, canvas.height));
      }
      
      // Small random changes to velocity for more dynamic movement
      this.vx += (Math.random() - 0.5) * 0.03;
      this.vy += (Math.random() - 0.5) * 0.03;
      
      // Keep velocity in bounds
      this.vx = Math.max(-1, Math.min(1, this.vx));
      this.vy = Math.max(-1, Math.min(1, this.vy));
    }
  }
  
  // Create particles
  const particleCount = 80;
  const particles = [];
  
  for (let i = 0; i < particleCount; i++) {
    particles.push(new Particle());
  }
  
  // Draw connections between particles
  function drawConnections() {
    ctx.strokeStyle = '#00FF41';
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        
        // Draw connections only between nearby particles
        if (distance < 150) {
          // Opacity based on distance - closer is more opaque
          const opacity = (150 - distance) / 150 * 0.35;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(0, 255, 65, ${opacity})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
  }
  
  // Animation loop
  function animate() {
    // Semi-transparent background to create trail effect
    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    // Occasionally add matrix-style falling characters
    if (Math.random() < 0.2) {
      const x = Math.random() * canvas.width;
      const y = Math.random() * canvas.height;
      const char = String.fromCharCode(33 + Math.floor(Math.random() * 94)); // Random ASCII character
      ctx.fillStyle = '#00FF41';
      ctx.font = '12px monospace';
      ctx.fillText(char, x, y);
    }
    
    // Update and draw particles
    particles.forEach(particle => {
      particle.update();
      particle.draw();
    });
    
    // Draw connections
    drawConnections();
    
    requestAnimationFrame(animate);
  }
  
  // Start animation
  animate();
};

// Initialize after page load
if (document.readyState === 'complete') {
  matrixBackground();
} else {
  window.addEventListener('load', matrixBackground);
}