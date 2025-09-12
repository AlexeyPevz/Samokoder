import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { HeroSection } from "@/components/home/HeroSection"
import { ExamplePrompts } from "@/components/home/ExamplePrompts"
import { TemplateGallery } from "@/components/home/TemplateGallery"
import { BenefitsSection } from "@/components/home/BenefitsSection"

export function Home() {
  const navigate = useNavigate()
  const [appDescription, setAppDescription] = useState("")
  const [isCreating, setIsCreating] = useState(false)

  const handleCreateApp = async () => {
    if (!appDescription.trim()) return
    
    setIsCreating(true)
    
    // Simulate app creation
    setTimeout(() => {
      setIsCreating(false)
      navigate("/dashboard")
    }, 2000)
  }

  const handleExampleClick = (example: string) => {
    setAppDescription(example)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      <HeroSection 
        appDescription={appDescription}
        setAppDescription={setAppDescription}
        onCreateApp={handleCreateApp}
        isCreating={isCreating}
      />
      
      <ExamplePrompts onExampleClick={handleExampleClick} />
      
      <TemplateGallery />
      
      <BenefitsSection />
    </div>
  )
}