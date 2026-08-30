declare module 'react-simple-maps' {
  import * as React from 'react'

  export interface GeographyShape {
    rsmKey: string
    properties: Record<string, any>
    [key: string]: any
  }

  export interface ComposableMapProps {
    projection?: string
    projectionConfig?: Record<string, any>
    width?: number
    height?: number
    style?: React.CSSProperties
    children?: React.ReactNode
  }

  export interface GeographiesProps {
    geography: string | Record<string, any>
    children: (props: { geographies: GeographyShape[]; projection: (coords: [number, number]) => [number, number] }) => React.ReactNode
  }

  export interface GeographyProps {
    geography: GeographyShape
    fill?: string
    stroke?: string
    strokeWidth?: number
    [key: string]: any
  }

  export interface MarkerProps {
    coordinates: [number, number]
    children?: React.ReactNode
    [key: string]: any
  }

  export const ComposableMap: React.FC<ComposableMapProps>
  export const Geographies: React.FC<GeographiesProps>
}
