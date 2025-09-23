// Tab Debugging Script
// Run this in browser console to diagnose tab visibility issues

console.log('🔍 Starting Tab Debug Analysis...');

// Function to analyze tab state
function debugTabState() {
    console.log('\n=== TAB DEBUG ANALYSIS ===');

    // 1. Check if tabs exist
    const allTabs = document.querySelectorAll('.tab-content');
    console.log(`📊 Found ${allTabs.length} tab elements`);

    allTabs.forEach((tab, index) => {
        const id = tab.id;
        const rect = tab.getBoundingClientRect();
        const computed = window.getComputedStyle(tab);

        console.log(`\n📋 Tab ${index + 1}: ${id}`);
        console.log(`   - Display: ${computed.display}`);
        console.log(`   - Visibility: ${computed.visibility}`);
        console.log(`   - Opacity: ${computed.opacity}`);
        console.log(`   - Width: ${computed.width} (${rect.width}px)`);
        console.log(`   - Height: ${computed.height} (${rect.height}px)`);
        console.log(`   - Position: ${rect.x}, ${rect.y}`);
        console.log(`   - Classes: ${tab.className}`);
        console.log(`   - Content length: ${tab.innerHTML.length} chars`);
        console.log(`   - Overflow: ${computed.overflow}`);
        console.log(`   - Z-index: ${computed.zIndex}`);

        // Check if content is actually there
        const textContent = tab.textContent.trim();
        console.log(`   - Text content: ${textContent.length > 0 ? 'YES' : 'NO'} (${textContent.length} chars)`);

        // Check parent container
        const parent = tab.parentElement;
        if (parent) {
            const parentRect = parent.getBoundingClientRect();
            const parentStyle = window.getComputedStyle(parent);
            console.log(`   - Parent: ${parent.className}`);
            console.log(`   - Parent display: ${parentStyle.display}`);
            console.log(`   - Parent dimensions: ${parentRect.width}x${parentRect.height}`);
        }
    });

    // 2. Check active tab specifically
    const activeTab = document.querySelector('.tab-content.active');
    if (activeTab) {
        console.log(`\n✅ Active tab: ${activeTab.id}`);

        // Force make it visible and report
        console.log('🔧 Attempting to force visibility...');
        activeTab.style.cssText = `
            display: block !important;
            opacity: 1 !important;
            visibility: visible !important;
            width: 100% !important;
            min-height: 500px !important;
            overflow: visible !important;
            background: rgba(255,0,0,0.1) !important;
            border: 2px solid red !important;
        `;

        // Check again after forcing
        const newRect = activeTab.getBoundingClientRect();
        console.log(`   - After force - Width: ${newRect.width}px, Height: ${newRect.height}px`);
        console.log(`   - After force - Visible: ${newRect.width > 0 && newRect.height > 0 ? 'YES' : 'NO'}`);

    } else {
        console.log('\n❌ No active tab found');
    }

    // 3. Check main container
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        const mainRect = mainContent.getBoundingClientRect();
        const mainStyle = window.getComputedStyle(mainContent);
        console.log(`\n🏠 Main container:`);
        console.log(`   - Dimensions: ${mainRect.width}x${mainRect.height}`);
        console.log(`   - Display: ${mainStyle.display}`);
        console.log(`   - Overflow: ${mainStyle.overflow}`);
    }

    return {
        totalTabs: allTabs.length,
        activeTab: activeTab ? activeTab.id : null,
        hasContent: activeTab ? activeTab.innerHTML.length > 0 : false
    };
}

// Function to test tab switching
function testTabSwitching() {
    console.log('\n🔄 Testing tab switching...');

    const tabButtons = document.querySelectorAll('.tab-item');
    console.log(`Found ${tabButtons.length} tab buttons`);

    tabButtons.forEach(button => {
        const tabId = button.id.replace('tab-', '');
        console.log(`📌 Button: ${button.textContent.trim()} -> ${tabId}`);
    });

    // Try switching to approvals tab
    console.log('\n🎯 Switching to approvals tab...');
    if (window.switchTab) {
        window.switchTab('approvals');
        setTimeout(() => {
            const result = debugTabState();
            console.log('\n📊 Result after switching:', result);
        }, 1000);
    } else {
        console.log('❌ switchTab function not found');
    }
}

// Run initial analysis
const initialResult = debugTabState();
console.log('\n📊 Initial analysis complete');

// Test tab switching after a delay
setTimeout(testTabSwitching, 2000);

console.log('\n🎯 Debug script loaded. Results will appear above.');
console.log('💡 You can also run debugTabState() manually anytime.');

// Make functions available globally
window.debugTabState = debugTabState;
window.testTabSwitching = testTabSwitching;